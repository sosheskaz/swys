package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPDataShortAliasPreservesExplicitEmptyData(t *testing.T) {
	t.Parallel()

	requestMethod := make(chan string, 1)
	requestBody := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		requestMethod <- request.Method
		requestBody <- body
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	_, _, err := executeRootStreams(t, "http", server.URL, "-X", "POST", "-d", "")
	require.NoError(t, err, "explicit empty -d: %v", err)
	require.Equal(t, http.MethodPost, <-requestMethod)
	require.Empty(t, <-requestBody)
}

func TestHTTPDataShortAliasRequiresExplicitMethodLikeData(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	_, _, longErr := executeRootStreams(t, "http", server.URL, "--data", "")
	_, _, shortErr := executeRootStreams(t, "http", server.URL, "-d", "")
	require.Error(t, longErr, "--data requires -X")
	require.EqualError(t, shortErr, longErr.Error(), "-d and --data reject missing method identically")
	require.Zero(t, requests.Load(), "requests")
}

func TestHTTPDataShortAliasConflictsWithInputBeforeRequestOrOutput(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	output := filepath.Join(directory, "output")
	require.NoError(t, os.WriteFile(input, []byte("from file"), 0o600))
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))

	_, _, err := executeRootStreams(t, "http", server.URL, "-d", "literal", "--input", input, "--output", output)
	require.Error(t, err)
	require.Zero(t, requests.Load(), "requests")
	content, readErr := os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, "preserve", string(content), "preserved output")
}

func TestHTTPDataShortAliasIsExactDataSynonym(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	command, _, err := root.Find([]string{httpCommandName})
	require.NoError(t, err)
	require.NotNil(t, command)
	require.Equal(t, httpCommandName, command.Name())
	data := command.Flags().Lookup("data")
	if data == nil {
		data = command.PersistentFlags().Lookup("data")
	}
	require.NotNil(t, data, "--data flag")
	require.Equal(t, "d", data.Shorthand)
}
