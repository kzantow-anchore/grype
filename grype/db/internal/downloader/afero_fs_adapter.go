package downloader

import (
	"github.com/spf13/afero"
	"io/fs"
	"os"
	"time"
)

func AferoAdapter(f fs.FS) afero.Fs {
}

type fileAdapter struct {
	fs   fs.FS
	path string
	f    fs.File
}

func (f *fileAdapter) Close() error {
	return f.f.Close()
}

func (f *fileAdapter) Read(p []byte) (n int, err error) {
	return f.f.Read(p)
}

func (f *fileAdapter) ReadAt(p []byte, off int64) (n int, err error) {
	if f, ok := f.f.(interface {
		ReadAt(p []byte, off int64) (n int, err error)
	}); ok {
		return f.ReadAt(p, off)
	}
	panic("not implemented")
}

func (f *fileAdapter) Seek(offset int64, whence int) (int64, error) {
	if f, ok := f.f.(interface {
		Seek(int64, int) (n int64, err error)
	}); ok {
		return f.Seek(offset, whence)
	}
	panic("not implemented")
}

func (f *fileAdapter) Write(p []byte) (n int, err error) {
	if f, ok := f.f.(interface {
		Write(p []byte) (n int, err error)
	}); ok {
		return f.Write(p)
	}
	panic("not implemented")
}

func (f *fileAdapter) WriteAt(p []byte, off int64) (n int, err error) {
	if f, ok := f.f.(interface {
		WriteAt(p []byte, off int64) (n int, err error)
	}); ok {
		return f.WriteAt(p, off)
	}
	panic("not implemented")
}

func (f *fileAdapter) Name() string {
	if f, ok := f.f.(interface {
		Name() string
	}); ok {
		return f.Name()
	}
	panic("not implemented")
}

func (f *fileAdapter) Readdir(count int) ([]os.FileInfo, error) {
	if f, ok := f.f.(interface {
		Readdir(count int) ([]os.FileInfo, error)
	}); ok {
		return f.Readdir(count)
	}
	panic("not implemented")
}

func (f *fileAdapter) Readdirnames(n int) ([]string, error) {
	if f, ok := f.f.(interface {
		Readdirnames(n int) ([]string, error)
	}); ok {
		return f.Readdirnames(n)
	}
	panic("not implemented")
}

func (f *fileAdapter) Stat() (os.FileInfo, error) {
	if f, ok := f.f.(interface {
		Stat() (os.FileInfo, error)
	}); ok {
		return f.Stat()
	}
	panic("not implemented")
}

func (f *fileAdapter) Sync() error {
	if f, ok := f.f.(interface {
		Sync() error
	}); ok {
		return f.Sync()
	}
	panic("not implemented")
}

func (f *fileAdapter) Truncate(size int64) error {
	if f, ok := f.f.(interface {
		Truncate(size int64) error
	}); ok {
		return f.Truncate(size)
	}
	panic("not implemented")
}

func (f *fileAdapter) WriteString(s string) (ret int, err error) {
	if f, ok := f.f.(interface {
		WriteString(s string) (ret int, err error)
	}); ok {
		return f.WriteString(s)
	}
	panic("not implemented")
}

var _ afero.File = (*fileAdapter)(nil)

type fsAdapter struct {
	fs fs.FS
}

func (f *fsAdapter) Create(name string) (afero.File, error) {
	file, err := f.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &fileAdapter{
		fs:   f.fs,
		path: name,
		f:    file,
	}, nil
}

func (f *fsAdapter) Mkdir(name string, perm os.FileMode) error {
	f.fs.Mkdir
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) MkdirAll(path string, perm os.FileMode) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Open(name string) (afero.File, error) {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Remove(name string) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) RemoveAll(path string) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Rename(oldname, newname string) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Stat(name string) (os.FileInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Name() string {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Chmod(name string, mode os.FileMode) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Chown(name string, uid, gid int) error {
	//TODO implement me
	panic("implement me")
}

func (f *fsAdapter) Chtimes(name string, atime time.Time, mtime time.Time) error {
	//TODO implement me
	panic("implement me")
}

var _ afero.Fs = (*fsAdapter)(nil)
