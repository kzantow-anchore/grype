package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hako/durafmt"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	archiver "github.com/mholt/archiver/v3"
	"github.com/spf13/afero"
	partybus "github.com/wagoodman/go-partybus"
	progress "github.com/wagoodman/go-progress"

	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/store"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

const (
	FileName = grypeDB.VulnerabilityStoreFileName
)

type Config struct {
	DBRootDir           string
	ListingURL          string
	CACert              string
	ValidateByHashOnGet bool
	ValidateAge         bool
	MaxAllowedBuiltAge  time.Duration
	RequireUpdateCheck  bool
	ListingFileTimeout  time.Duration
	UpdateTimeout       time.Duration
}

type Curator struct {
	fs                  afero.Fs
	stage               progress.AtomicStage
	httpClient          *http.Client
	listingDownloader   file.Getter
	updateDownloader    file.Getter
	targetSchema        int
	dbDir               string
	dbPath              string
	listingURL          string
	validateByHashOnGet bool
	validateAge         bool
	maxAllowedBuiltAge  time.Duration
	requireUpdateCheck  bool
}

func NewCurator(cfg Config) (Curator, error) {
	dbDir := path.Join(cfg.DBRootDir, strconv.Itoa(vulnerability.SchemaVersion))

	fs := afero.NewOsFs()
	listingClient, err := defaultHTTPClient(fs, cfg.CACert, cfg.ListingFileTimeout)
	if err != nil {
		return Curator{}, err
	}

	dbClient, err := defaultHTTPClient(fs, cfg.CACert, cfg.UpdateTimeout)
	if err != nil {
		return Curator{}, err
	}

	return Curator{
		fs:                  fs,
		targetSchema:        vulnerability.SchemaVersion,
		httpClient:          listingClient,
		listingDownloader:   file.NewGetter(listingClient),
		updateDownloader:    file.NewGetter(dbClient),
		dbDir:               dbDir,
		dbPath:              path.Join(dbDir, FileName),
		listingURL:          cfg.ListingURL,
		validateByHashOnGet: cfg.ValidateByHashOnGet,
		validateAge:         cfg.ValidateAge,
		maxAllowedBuiltAge:  cfg.MaxAllowedBuiltAge,
		requireUpdateCheck:  cfg.RequireUpdateCheck,
	}, nil
}

func (c Curator) SupportedSchema() int {
	return c.targetSchema
}

func (c *Curator) GetStore() (grypeDB.StoreReader, grypeDB.DBCloser, error) {
	// ensure the DB is ok
	_, err := c.validateIntegrity(executionContext{ctx: context.Background()}, c.dbDir)
	if err != nil {
		return nil, nil, fmt.Errorf("vulnerability database is invalid (run db update to correct): %+v", err)
	}

	s, err := store.New(c.dbPath, false)
	return s, s, err
}

func (c *Curator) Status() Status {
	metadata, err := NewMetadataFromDir(c.fs, c.dbDir)
	if err != nil {
		return Status{
			Err: fmt.Errorf("failed to parse database metadata (%s): %w", c.dbDir, err),
		}
	}
	if metadata == nil {
		return Status{
			Err: fmt.Errorf("database metadata not found at %q", c.dbDir),
		}
	}

	return Status{
		Built:         metadata.Built,
		SchemaVersion: metadata.Version,
		Location:      c.dbDir,
		Checksum:      metadata.Checksum,
		Err:           c.Validate(),
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.dbDir)
}

// Update the existing DB, returning an indication if any action was taken.
func (c *Curator) Update() (bool, error) {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := progress.NewManual(1)
	stage := progress.NewAtomicStage("checking for update")
	downloadProgress := progress.NewManual(1)
	aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, importProgress)

	bus.Publish(partybus.Event{
		Type: event.UpdateVulnerabilityDatabase,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: progress.Progressable(aggregateProgress),
		}),
	})

	defer downloadProgress.SetCompleted()
	defer importProgress.SetCompleted()

	updateAvailable, metadata, updateEntry, err := c.IsUpdateAvailable()
	if err != nil {
		if c.requireUpdateCheck {
			return false, fmt.Errorf("check for vulnerability database update failed: %+v", err)
		}
		log.Warnf("unable to check for vulnerability database update")
		log.Debugf("check for vulnerability update failed: %+v", err)
	}
	if updateAvailable {
		log.Infof("downloading new vulnerability DB")
		err = c.UpdateTo(updateEntry, downloadProgress, importProgress, stage)
		if err != nil {
			return false, fmt.Errorf("unable to update vulnerability database: %w", err)
		}

		if metadata != nil {
			log.Infof(
				"updated vulnerability DB from version=%d built=%q to version=%d built=%q",
				metadata.Version,
				metadata.Built.String(),
				updateEntry.Version,
				updateEntry.Built.String(),
			)
			return true, nil
		}

		log.Infof(
			"downloaded new vulnerability DB version=%d built=%q",
			updateEntry.Version,
			updateEntry.Built.String(),
		)
		return true, nil
	}

	stage.Set("no update available")
	return false, nil
}

// IsUpdateAvailable indicates if there is a new update available as a boolean, and returns the latest listing information
// available for this schema.
func (c *Curator) IsUpdateAvailable() (bool, *Metadata, *ListingEntry, error) {
	log.Debugf("checking for available database updates")

	listing, err := c.ListingFromURL()
	if err != nil {
		return false, nil, nil, err
	}

	updateEntry := listing.BestUpdate(c.targetSchema)
	if updateEntry == nil {
		return false, nil, nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	current, err := NewMetadataFromDir(c.fs, c.dbDir)
	if err != nil {
		return false, nil, nil, fmt.Errorf("current metadata corrupt: %w", err)
	}

	if current.IsSupersededBy(updateEntry) {
		log.Debugf("database update available: %s", updateEntry)
		return true, current, updateEntry, nil
	}
	log.Debugf("no database update available")

	return false, nil, nil, nil
}

// UpdateTo updates the existing DB with the specific other version provided from a listing entry.
func (c *Curator) UpdateTo(listing *ListingEntry, downloadProgress, importProgress *progress.Manual, stage *progress.AtomicStage) error {
	stage.Set("downloading")
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempArchivePath, err := c.downloadListingEntry(listing, downloadProgress)
	if err != nil {
		return err
	}

	stage.Set("importing")
	err = c.ImportFrom(tempArchivePath, importProgress, stage)
	if err != nil {
		return err
	}

	stage.Set("updated")
	importProgress.Set(importProgress.Size())
	importProgress.SetCompleted()

	// only remove the temp archive on success
	return c.fs.RemoveAll(tempArchivePath)
}

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *Curator) Validate(ctx context.Context) error {
	metadata, err := c.validateIntegrity(executionContext{ctx: ctx}, c.dbDir)
	if err != nil {
		return err
	}

	return c.validateStaleness(metadata)
}

func (c *Curator) tempDownloadPath(fileName string) string {
	return filepath.Join(c.dbDir, fileName) + ".temp"
}

func (c *Curator) tempDbDir() string {
	return c.dbDir + ".temp"
}

// ImportFrom takes a DB archive file and imports it into the final DB location.
func (c *Curator) ImportFrom(dbArchivePath string, importProgress *progress.Manual, stage *progress.AtomicStage) error {
	f, err := os.Open(dbArchivePath)
	if err != nil {
		return err
	}

	return c.extractDBArchivetoDBDir(dbArchivePath, f, importProgress, stage)
}

func (c *Curator) extractDBArchivetoDBDir(ctx executionContext, fileName string, f io.ReadCloser) error {
	err := extractToDir(fileName, f, c.fs, c.tempDbDir())
	if err != nil {
		return err
	}

	_, err = c.validateIntegrity(ctx, c.tempDbDir())
	if err != nil {
		return err
	}

	bakDir := c.dbDir + ".bak"
	err = moveFile(c.fs, c.dbDir, bakDir)
	if err != nil {
		return err
	}

	err = moveFile(c.fs, c.tempDbDir(), c.dbDir)
	if err != nil {
		return err
	}

	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	err = c.fs.RemoveAll(bakDir)
	if err != nil {
		log.Warnf("unable to remove temporary directory: %v", err)
	}
	return nil

}

func moveFile(fs afero.Fs, from string, to string) error {
	if s, err := fs.Stat(to); err == nil && s.IsDir() {
		err = fs.RemoveAll(to)
		if err != nil {
			log.Warnf("unable to remove existing dir: %v", err)
		}
	}
	return fs.Rename(from, to)
}

func extractToDir(fileName string, reader io.ReadCloser, fsys afero.Fs, destinationDir string) error {
	fileName = path.Base(filepath.Base(fileName))
	unarchiver, err := archiver.ByExtension(fileName)

	if err != nil {
		return err
	}
	rdr, ok := unarchiver.(archiver.Reader)
	if !ok {
		// TODO try different formats
		return fmt.Errorf("format specified by source filename is not an archive format: %s (%T)", fileName, unarchiver)
	}

	err = rdr.Open(reader, 0)
	if err != nil {
		return fmt.Errorf("opening archive: %v", err)
	}
	defer func() {
		err := reader.Close()
		if err != nil {
			log.Debugf("unable to close archive reader: %v", err)
		}
	}()
	destinationDir = filepath.Clean(destinationDir)
	for f, err := rdr.Read(); err == nil; f, err = rdr.Read() {
		targetPath := filepath.Clean(filepath.Join(destinationDir, f.Name()))
		if !strings.HasPrefix(targetPath, destinationDir) {
			log.Debugf("skipping file which would be written outside of desitination directory: %v", f.Name())
			continue
		}
		targetFile, err := fsys.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, f.Mode())
		_, err = io.Copy(targetFile, f)
		if err != nil {
			log.Warnf("unable to write to file: %v: %v", targetPath, err)
			continue
		}
		closeAndLogError(targetFile)
		err = fsys.Chtimes(targetPath, f.ModTime(), f.ModTime())
		if err != nil {
			log.Tracef("unable to chtimes: %v: %v", targetPath, err)
		}
	}
	return nil
}

func (c *Curator) downloadListingEntry(ctx executionContext, listing *ListingEntry) (string, error) {
	if listing == nil || listing.URL == nil {
		return "", fmt.Errorf("no URL provided in listing entry")
	}

	targetFileName := path.Base(listing.URL.Path)
	targetFileName = filepath.Join(c.dbDir, targetFileName)

	// download the db a temporary file in the cache dir
	err := c.download(ctx, listing.URL, targetFileName, listing.Checksum)

	if err != nil {
		return filePath, err
	}

	return filePath, nil
}

func (c *Curator) download(ctx executionContext, url *url.URL, targetPath string, checksum string) error {
	if url == nil {
		return fmt.Errorf("no URL provided")
	}
	dl := downloader{
		fs:      c.fs,
		ctx:     ctx.ctx,
		notify:  nil,
		retries: 0,
		timeout: 0,
	}

	return nil
}

// validateStaleness ensures the vulnerability database has not passed
// the max allowed age, calculated from the time it was built until now.
func (c *Curator) validateStaleness(m Metadata) error {
	// built time is defined in UTC,
	// we should compare it against UTC
	now := time.Now().UTC()

	age := now.Sub(m.Built)
	if age > c.maxAllowedBuiltAge {
		return fmt.Errorf("the vulnerability database was built %s ago (max allowed age is %s)", durafmt.ParseShort(age), durafmt.ParseShort(c.maxAllowedBuiltAge))
	}

	return nil
}

func (c *Curator) validateIntegrity(ctx executionContext, dbDirPath string) (Metadata, error) {
	// check that the disk checksum still matches the db payload
	metadata, err := NewMetadataFromDir(c.fs, dbDirPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to parse database metadata (%s): %w", dbDirPath, err)
	}
	if metadata == nil {
		return Metadata{}, fmt.Errorf("database metadata not found: %s", dbDirPath)
	}

	dbPath := path.Join(dbDirPath, FileName)
	valid, actualHash, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
	if err != nil {
		return Metadata{}, err
	}
	if !valid {
		return Metadata{}, fmt.Errorf("bad db checksum (%s): %q vs %q", dbPath, metadata.Checksum, actualHash)
	}

	if c.targetSchema != metadata.Version {
		return Metadata{}, fmt.Errorf("unsupported database version: have=%d want=%d", metadata.Version, c.targetSchema)
	}

	// TODO: add version checks here to ensure this version of the application can use this database version (relative to what the DB says, not JUST the metadata!)

	return *metadata, nil
}

//// activate swaps over the downloaded db to the application directory
//func (c *Curator) activate(dbDirPath string) error {
//	_, err := c.fs.Stat(c.dbDir)
//	if !os.IsNotExist(err) {
//		// remove any previous databases
//		err = c.Delete()
//		if err != nil {
//			return fmt.Errorf("failed to purge existing database: %w", err)
//		}
//	}
//
//	// ensure there is an application db directory
//	err = c.fs.MkdirAll(c.dbDir, 0755)
//	if err != nil {
//		return fmt.Errorf("failed to create db directory: %w", err)
//	}
//
//	// activate the new db cache
//	return file.CopyDir(c.fs, dbDirPath, c.dbDir)
//}

// ListingFromURL loads a Listing from a URL.
func (c Curator) ListingFromURL() (Listing, error) {
	tempFile, err := afero.TempFile(c.fs, "", "grype-db-listing")
	if err != nil {
		return Listing{}, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer func() {
		err := c.fs.RemoveAll(tempFile.Name())
		if err != nil {
			log.Errorf("failed to remove file (%s): %w", tempFile.Name(), err)
		}
	}()

	// download the listing file
	err = c.listingDownloader.GetFile(tempFile.Name(), c.listingURL)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := NewListingFromFile(c.fs, tempFile.Name())
	if err != nil {
		return Listing{}, err
	}
	return listing, nil
}

func defaultHTTPClient(fs afero.Fs, caCertPath string, timeout time.Duration) (*http.Client, error) {
	httpClient := cleanhttp.DefaultClient()
	httpClient.Timeout = timeout

	tx, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unable to get http.Transport")
	}
	tx.IdleConnTimeout = timeout
	tx.ExpectContinueTimeout = timeout
	tx.ResponseHeaderTimeout = timeout
	tx.TLSHandshakeTimeout = timeout

	if caCertPath != "" {
		rootCAs := x509.NewCertPool()

		pemBytes, err := afero.ReadFile(fs, caCertPath)
		if err != nil {
			return nil, fmt.Errorf("unable to configure root CAs for curator: %w", err)
		}
		rootCAs.AppendCertsFromPEM(pemBytes)

		tx.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		}
	}
	return httpClient, nil
}
