//go:build unix

package http

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errHTTPFIFOReadCanceled = errors.New("HTTP FIFO read canceled")

func TestHTTPFileBodyReadCancellationClosesFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "body.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	ctx, cancel := context.WithCancelCause(t.Context())
	t.Cleanup(func() { cancel(nil) })
	type openedBody struct {
		body *httpBody
		err  error
	}
	bodyReady := make(chan openedBody, 1)
	go func() {
		body, err := httpFileBody(ctx, path, func(reader io.Reader) io.Reader { return reader }, true)
		bodyReady <- openedBody{body: body, err: err}
	}()

	type openedFile struct {
		file *os.File
		err  error
	}
	writerReady := make(chan openedFile, 1)
	go func() {
		writer, err := os.OpenFile(path, os.O_WRONLY, 0)
		writerReady <- openedFile{file: writer, err: err}
	}()

	var body *httpBody
	select {
	case result := <-bodyReady:
		if result.err != nil {
			t.Fatalf("open FIFO body: %v", result.err)
		}
		body = result.body
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP body did not open the FIFO")
	}
	var writer *os.File
	select {
	case result := <-writerReady:
		if result.err != nil {
			t.Fatalf("open FIFO writer: %v", result.err)
		}
		writer = result.file
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO writer did not open")
	}
	t.Cleanup(func() {
		if writer != nil {
			_ = writer.Close() //nolint:errcheck // test cleanup is best effort
		}
		if body != nil {
			_ = body.Close() //nolint:errcheck // test cleanup is best effort
		}
	})

	if _, err := writer.Write([]byte{'x'}); err != nil {
		t.Fatalf("seed FIFO body: %v", err)
	}
	buffer := make([]byte, 1)
	if n, err := body.Read(buffer); n != 1 || err != nil || buffer[0] != 'x' {
		t.Fatalf("initial FIFO Read = (%q, %v), want (x, nil)", buffer[:n], err)
	}

	type readResult struct {
		err error
		n   int
	}
	readStarted := make(chan struct{})
	readDone := make(chan readResult, 1)
	go func() {
		close(readStarted)
		n, err := body.Read(make([]byte, 1))
		readDone <- readResult{n: n, err: err}
	}()
	<-readStarted

	cancel(errHTTPFIFOReadCanceled)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	var result readResult
	timedOut := false
	select {
	case result = <-readDone:
	case <-timer.C:
		timedOut = true
	}

	// Release and join a reader that lacks cancellation support before failing.
	if timedOut {
		closeErr := writer.Close()
		writer = nil
		select {
		case <-readDone:
		case <-time.After(5 * time.Second):
			t.Fatal("FIFO reader remained blocked after cleanup")
		}
		require.NoError(t, closeErr, "close FIFO writer during cleanup")
		t.Fatal("FIFO read stayed blocked after context cancellation")
	}

	if result.n != 0 || !errors.Is(result.err, errHTTPFIFOReadCanceled) {
		t.Fatalf("canceled FIFO Read = (%d, %v), want (0, cancellation cause)", result.n, result.err)
	}
}
