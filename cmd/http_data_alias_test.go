package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
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
	if err != nil {
		t.Fatalf("explicit empty -d: %v", err)
	}
	if method := <-requestMethod; method != http.MethodPost {
		t.Fatalf("method = %q, want POST", method)
	}
	if body := <-requestBody; len(body) != 0 {
		t.Fatalf("body = %q, want explicitly empty body", body)
	}
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
	if longErr == nil || shortErr == nil {
		t.Fatalf("no-method errors: --data=%v, -d=%v; both must require -X", longErr, shortErr)
	}
	if longErr.Error() != shortErr.Error() {
		t.Fatalf("no-method errors differ: --data=%q, -d=%q", longErr, shortErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("server received %d requests, want zero", requests.Load())
	}
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
	if err := os.WriteFile(input, []byte("from file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := executeRootStreams(t, "http", server.URL, "-d", "literal", "--input", input, "--output", output)
	if err == nil {
		t.Fatal("-d with --input succeeded, want conflict")
	}
	if requests.Load() != 0 {
		t.Fatalf("server received %d requests, want zero", requests.Load())
	}
	content, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "preserve" {
		t.Fatalf("output = %q, want preserved existing content", content)
	}
}

func TestHTTPDataShortAliasIsExactDataSynonym(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	command, _, err := root.Find([]string{httpCommandName})
	if err != nil || command == nil || command.Name() != httpCommandName {
		t.Fatalf("find HTTP command: command=%v error=%v", command, err)
	}
	data := command.Flags().Lookup("data")
	if data == nil {
		data = command.PersistentFlags().Lookup("data")
	}
	if data == nil {
		t.Fatal("--data flag is missing")
	}
	if data.Shorthand != "d" {
		t.Fatalf("--data shorthand = %q, want exact -d synonym", data.Shorthand)
	}
}
