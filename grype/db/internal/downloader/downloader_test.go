package downloader

import (
	"context"
	"embed"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"testing/fstest"
)

//go:embed test-fixtures/files/*
var testFixtureFS embed.FS

func Test_downloader(t *testing.T) {
	fsHandler := http.FileServerFS(testFixtureFS)
	server := httptest.NewServer(fsHandler)
	defer server.Close()

	somethingContents, err := os.ReadFile("test-fixtures/files/something.json")
	require.NoError(t, err)

	downloadFile := "my-download-file.json"
	downloadFileTemp := downloadFile + downloadSuffix

	tests := []struct {
		name    string
		fs      fs.FS
		server  *httptest.Server
		want    []byte
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "no file",
			fs: fstest.MapFS{
				downloadFileTemp: &fstest.MapFile{
				},
			},
			server: server,
		},
		{
			name: "partial file",
			fs: fstest.MapFS{
				downloadFileTemp: &fstest.MapFile{
					Data: somethingContents[0:20],
				},
			},
			server: server,
		},
		{
			name: "complete file",
			fs: fstest.MapFS{
				downloadFileTemp: &fstest.MapFile{
					Data: somethingContents,
				},
			},
			server: server,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dl := NewDownloader(context.TODO()).WithFS(AferoAdapter(test.fs))

			dl.
		})
	}
}
