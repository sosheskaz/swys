//go:build unix

package contextio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestOwnedFileReaderFIFOStreamsToEOF(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 32*1024 - 1, 32 * 1024, 32*1024 + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			reader, _, writer := openOwnedTestFIFO(ctx, t)
			payload := make([]byte, size)
			for index := range payload {
				payload[index] = byte(index % 251)
			}
			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := io.Copy(writer, bytes.NewReader(payload))
				writeDone <- errors.Join(writeErr, writer.Close())
			}()

			data, readErr := io.ReadAll(reader)
			if readErr != nil {
				_ = reader.Close() //nolint:errcheck // release the writer before reporting the read failure
				_ = writer.Close() //nolint:errcheck // release a blocked write before joining it
			}
			var writeErr error
			select {
			case writeErr = <-writeDone:
			case <-time.After(5 * time.Second):
				_ = reader.Close() //nolint:errcheck // best effort after a test timeout
				_ = writer.Close() //nolint:errcheck // best effort after a test timeout
				select {
				case <-writeDone:
				case <-time.After(5 * time.Second):
					t.Fatal("FIFO writer remained blocked after cleanup")
				}
				t.Fatal("FIFO writer did not finish after the reader reached EOF")
			}
			if readErr != nil || writeErr != nil {
				t.Fatalf("FIFO transfer errors = (read %v, write %v)", readErr, writeErr)
			}
			if !bytes.Equal(data, payload) {
				t.Fatalf("FIFO data length/content = %d/%t, want %d/true", len(data), bytes.Equal(data, payload), len(payload))
			}
			if err := reader.Close(); err != nil {
				t.Fatalf("close FIFO reader: %v", err)
			}
		})
	}
}

func TestOwnedFileReaderFIFOCancellationClosesInput(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancelCause(t.Context())
	reader, input, writer := openOwnedTestFIFO(ctx, t)
	if _, err := writer.Write([]byte{'x'}); err != nil {
		t.Fatalf("seed FIFO: %v", err)
	}
	buffer := make([]byte, 1)
	if n, err := reader.Read(buffer); n != 1 || err != nil || buffer[0] != 'x' {
		t.Fatalf("initial FIFO Read = (%q, %v), want (x, nil)", buffer[:n], err)
	}

	readStarted := make(chan struct{})
	readDone := make(chan fifoReadResult, 1)
	go func() {
		close(readStarted)
		n, err := reader.Read(make([]byte, 1))
		readDone <- fifoReadResult{err: err, n: n}
	}()
	<-readStarted
	cancel(errOwnedFileCanceled)

	var result fifoReadResult
	select {
	case result = <-readDone:
	case <-time.After(2 * time.Second):
		if err := writer.Close(); err != nil {
			t.Fatalf("close FIFO writer during cleanup: %v", err)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("close FIFO reader during cleanup: %v", err)
		}
		select {
		case <-readDone:
		case <-time.After(5 * time.Second):
			t.Fatal("FIFO read remained blocked after cleanup")
		}
		t.Fatal("FIFO read stayed blocked after context cancellation")
	}
	if result.n != 0 || !errors.Is(result.err, errOwnedFileCanceled) {
		t.Fatalf("canceled FIFO Read = (%d, %v), want (0, cancellation cause)", result.n, result.err)
	}
	waitUntil(t, func() bool {
		_, err := input.Stat()
		return errors.Is(err, os.ErrClosed)
	}, "cancellation left the owned FIFO input open")
	if err := reader.Close(); err != nil {
		t.Fatalf("Close after cancellation: %v", err)
	}
}

func TestOwnedFileReaderCloseReleasesBlockedFIFORead(t *testing.T) {
	t.Parallel()
	reader, input, writer := openOwnedTestFIFO(t.Context(), t)
	if _, err := writer.Write([]byte{'x'}); err != nil {
		t.Fatalf("seed FIFO: %v", err)
	}
	buffer := make([]byte, 1)
	if n, err := reader.Read(buffer); n != 1 || err != nil || buffer[0] != 'x' {
		t.Fatalf("initial FIFO Read = (%q, %v), want (x, nil)", buffer[:n], err)
	}

	readStarted := make(chan struct{})
	readDone := make(chan fifoReadResult, 1)
	go func() {
		close(readStarted)
		n, err := reader.Read(make([]byte, 1))
		readDone <- fifoReadResult{err: err, n: n}
	}()
	<-readStarted
	firstErr := reader.Close()

	select {
	case result := <-readDone:
		if result.n != 0 || result.err == nil {
			t.Fatalf("Read released by Close = (%d, %v), want (0, non-nil error)", result.n, result.err)
		}
	case <-time.After(2 * time.Second):
		if err := writer.Close(); err != nil {
			t.Fatalf("close FIFO writer during cleanup: %v", err)
		}
		select {
		case <-readDone:
		case <-time.After(5 * time.Second):
			t.Fatal("FIFO read remained blocked after cleanup")
		}
		t.Fatal("Close did not release the blocked FIFO read")
	}
	if firstErr != nil {
		t.Fatalf("first Close = %v, want nil", firstErr)
	}
	if secondErr := reader.Close(); secondErr != nil {
		t.Fatalf("second Close = %v, want nil like the first Close", secondErr)
	}
	if _, err := input.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("owned FIFO Stat after Close = %v, want os.ErrClosed", err)
	}
}

type fifoReadResult struct {
	err error
	n   int
}

func openOwnedTestFIFO(ctx context.Context, t *testing.T) (io.ReadCloser, *os.File, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// A temporary read/write peer lets both real endpoints open synchronously;
	// it is gone before the test observes EOF, cancellation, or descriptor state.
	peer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open temporary FIFO peer: %v", err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatalf("open FIFO reader: %v", errors.Join(err, peer.Close()))
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open FIFO writer: %v", errors.Join(err, input.Close(), peer.Close()))
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close temporary FIFO peer: %v", errors.Join(err, input.Close(), writer.Close()))
	}
	reader, err := NewOwnedFileReader(ctx, input)
	if err != nil {
		if closeErr := writer.Close(); closeErr != nil {
			t.Errorf("close FIFO writer after constructor failure: %v", closeErr)
		}
		t.Fatalf("construct owned FIFO reader: %v", err)
	}
	t.Cleanup(func() {
		_ = writer.Close() //nolint:errcheck // test cleanup is best effort
		_ = reader.Close() //nolint:errcheck // test cleanup is best effort
	})
	return reader, input, writer
}
