package http_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPAutomaticResponseCompression(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "gzip" {
			http.Error(writer, "unexpected Accept-Encoding", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(writer)
		if _, err := io.WriteString(compressed, "compressed response\n"); err != nil {
			t.Errorf("compress example response: %v", err)
		}
		if err := compressed.Close(); err != nil {
			t.Errorf("close example compressor: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL)
	require.NoError(t, err, "npc http URL: %v", err)
	assert.Equal(t, "compressed response\n", stdout)
	assert.Empty(t, stderr)
}
