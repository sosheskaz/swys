package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestExampleHTTPAutomaticResponseCompression(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "gzip, br, zstd" {
			http.Error(writer, "unexpected Accept-Encoding", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Encoding", "br")
		compressed := brotli.NewWriter(writer)
		if _, err := io.WriteString(compressed, "compressed response\n"); err != nil {
			t.Errorf("compress example response: %v", err)
		}
		if err := compressed.Close(); err != nil {
			t.Errorf("close example compressor: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL)
	if err != nil {
		t.Fatalf("npc http URL: %v", err)
	}
	if stdout != "compressed response\n" {
		t.Fatalf("stdout = %q, want decompressed response", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}
