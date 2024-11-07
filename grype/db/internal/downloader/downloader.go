package downloader

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/afero"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Downloader interface {
	WithFS(fs afero.Fs) Downloader
	WithTransport(transport *http.Transport) Downloader
	WithNotify(notify func(msg any)) Downloader
	WithRetries(retries uint) Downloader
	WithTimeout(timeout time.Duration) Downloader
	GetFile(url, targetPath, expectedHash string) error
}

type downloader struct {
	ctx       context.Context
	fs        afero.Fs
	notify    func(msg any)
	transport *http.Transport
	retries   uint
	timeout   time.Duration
}

type DownloadPhase int

const (
	PhaseStarting DownloadPhase = iota
	PhaseDownloading
	PhaseComplete
)

type DownloadStatus struct {
	Phase       DownloadPhase
	Message     string
	Transferred uint
	Total       uint
}

func NewDownloader(ctx context.Context) Downloader {
	return &downloader{
		ctx:    ctx,
		fs:     afero.NewOsFs(),
		notify: func(_ any) {},
	}
}

func (d *downloader) WithFS(fs afero.Fs) Downloader {
	d.fs = fs
	return d
}

func (d *downloader) WithNotify(notify func(msg any)) Downloader {
	d.notify = notify
	return d
}

func (d *downloader) WithTransport(transport *http.Transport) Downloader {
	d.transport = transport
	return d
}

func (d *downloader) WithRetries(retries uint) Downloader {
	d.retries = retries
	return d
}

func (d *downloader) WithTimeout(timeout time.Duration) Downloader {
	d.timeout = timeout
	return d
}

const downloadSuffix = ".download"

// GetFile downloads a file at the given URL to the targetPath on the filesystem at d.fs, with an optional expected
// hash value in the form: <checksum-algorithm>:<hex-encoded-checksum>, e.g.: sha256:712a54ac9b4d7130f...
func (d *downloader) GetFile(url string, targetPath string, expectedHash string) error {
	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	dir := filepath.Dir(targetPath)
	if _, err := d.fs.Stat(dir); errors.Is(err, os.ErrNotExist) {
		err = d.fs.MkdirAll(dir, 0700|os.ModeDir)
	}

	if err != nil {
		return fmt.Errorf("unable to create download location: %w", err)
	}

	targetTempPath := targetPath + downloadSuffix

	resumeAt := int64(0)

	// check for partial download
	targetFileWriter, err := d.fs.OpenFile(targetTempPath, os.O_APPEND|os.O_RDWR, 0700)
	if err != nil {
		targetFileWriter, err = d.fs.OpenFile(targetTempPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0700)
	} else {
		// if we can read the file, get the size to resume download
		if s, err := targetFileWriter.Stat(); err == nil {
			resumeAt = s.Size()
			req.Header.Add("Range", fmt.Sprintf("bytes=%v-", resumeAt))
		} else {
			targetFileWriter, err = d.fs.OpenFile(targetTempPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0700)
		}
	}
	if err != nil {
		return fmt.Errorf("unable to create download file: %w", err)
	}

	client := http.DefaultClient
	if client == nil {
		client = &http.Client{}
	}

	if d.transport != nil {
		client.Transport = d.transport.Clone()
	} else if http.DefaultTransport != nil {
		client.Transport = http.DefaultTransport
	}

	if d.timeout > 0 {
		client.Timeout = d.timeout

		tx, ok := client.Transport.(*http.Transport)
		if ok {
			tx = tx.Clone()
			tx.IdleConnTimeout = d.timeout
			tx.ExpectContinueTimeout = d.timeout
			tx.ResponseHeaderTimeout = d.timeout
			tx.TLSHandshakeTimeout = d.timeout
		}
	}

	if resumeAt > 0 {
		d.notify(DownloadStatus{Phase: PhaseStarting, Message: "resuming download", Transferred: uint(resumeAt)})
	} else {
		d.notify(DownloadStatus{Phase: PhaseStarting, Message: "starting download"})
	}
	rsp, err := client.Do(req)

	// see if we're resuming a download: parse the header: Content-Range: <unit> <range-start>-<range-end>/<size>
	if rsp.StatusCode == http.StatusPartialContent {
		contentRange := rsp.Header.Get("Content-Range")
		parts := strings.Split(contentRange, " ")
		if len(parts) == 2 && parts[0] == "bytes" {
			parts = strings.Split(parts[1], "/")
			parts = strings.Split(parts[0], "-")
			startAt, err := strconv.Atoi(parts[0])
			// if the server indicates we should resume at a specific location that we have, use that
			if err == nil && startAt > 0 && int64(startAt) <= resumeAt {
				movedTo, err := targetFileWriter.Seek(int64(startAt), io.SeekStart)
				if movedTo > 0 && err == nil {
					err = targetFileWriter.Truncate(movedTo)
				} else {
					// if we have a bad offset, just delete the file and download fresh
					closeAndLogError(targetFileWriter)
					err = d.fs.Remove(targetTempPath)
					if err != nil {
						return fmt.Errorf("unable to remove file: %v: %v", targetTempPath, err)
					}
					return d.GetFile(url, targetPath, expectedHash)
				}
			}
		}
	}

	// concurrently hash the file as it's written, so we get the full contents whether it was resumed or fresh, and to save time
	var hasher func() ([]byte, error)
	if expectedHash != "" {
		var hashAlgorithm hash.Hash
		parts := strings.Split(expectedHash, ":")
		if len(parts) == 2 {
			expectedHash = parts[1]
			switch strings.ToLower(parts[0]) {
			case "sha1":
				hashAlgorithm = sha1.New()
			case "sha256":
				hashAlgorithm = sha256.New()
			default:
				return fmt.Errorf("unknown hash algorithm, not performing validation: %v", expectedHash)
			}
			if hashAlgorithm != nil {
				hasher = fileHasher(d.fs, targetTempPath, hashAlgorithm)
			}
		}
	}

	rdr := rsp.Body
	defer closeAndLogError(rdr)

	_, err = io.Copy(targetFileWriter, rdr)

	if hasher != nil {
		fileHash, err := hasher() // will block until hash complete
		if err != nil {
			return fmt.Errorf("error while hashing content, skipping verification: %v", err)
		}
		gotHash := hex.EncodeToString(fileHash)
		if expectedHash != gotHash {
			return fmt.Errorf("checksum mismatch: %v != %v", expectedHash, gotHash)
		}
	}

	return d.fs.Rename(targetTempPath, targetPath)
}

func fileHasher(fs afero.Fs, targetPath string, hasher hash.Hash) func() ([]byte, error) {
	var err error
	hashValue := make(chan []byte)
	go func() {
		defer close(hashValue)
		var f afero.File
		f, err = fs.Open(targetPath)
		if err != nil {
			return
		}
		_, err = io.Copy(hasher, f)
		hashValue <- hasher.Sum(nil)
	}()

	return func() ([]byte, error) {
		bytes := <-hashValue
		return bytes, err
	}
}

func closeAndLogError(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Debug(err)
	}
}
