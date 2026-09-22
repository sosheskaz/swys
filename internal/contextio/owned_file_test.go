package contextio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

var errOwnedFileCanceled = errors.New("owned file canceled")

func TestOwnedFileReaderCanceledConstructorClosesInput(t *testing.T) {
	t.Parallel()
	file := openOwnedTestFile(t, []byte("unread"))
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errOwnedFileCanceled)

	reader, err := NewOwnedFileReader(ctx, file)

	if reader != nil || !errors.Is(err, errOwnedFileCanceled) {
		if reader != nil {
			_ = reader.Close() //nolint:errcheck // reclaim an unexpected constructor result before failing
		}
		t.Fatalf("NewOwnedFileReader = (%v, %v), want (nil, cancellation cause)", reader, err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("owned input Stat after constructor failure = %v, want os.ErrClosed", err)
	}
}

func TestOwnedFileReaderStreamsRegularFilesWithoutReadAhead(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 32*1024 - 1, 32 * 1024, 32*1024 + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			content := make([]byte, size+1)
			for index := range content {
				content[index] = byte(index % 251)
			}
			file := openOwnedTestFile(t, content)
			reader, err := NewOwnedFileReader(nil, file) //nolint:staticcheck // nil context is an explicit supported input
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() }) //nolint:errcheck // test cleanup is best effort

			buffer := make([]byte, size)
			n, err := reader.Read(buffer)
			if n != size || err != nil || !bytes.Equal(buffer[:n], content[:size]) {
				t.Fatalf("Read(%d bytes) = (%d, %v), want unchanged requested bytes", size, n, err)
			}
			offset, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				t.Fatal(err)
			}
			if offset != int64(size) {
				t.Fatalf("file offset = %d, want %d so no bytes were read ahead", offset, size)
			}

			remainder, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(remainder, content[size:]) {
				t.Fatalf("remaining data = %x, want %x", remainder, content[size:])
			}
			if endN, endErr := reader.Read(make([]byte, 1)); endN != 0 || !errors.Is(endErr, io.EOF) {
				t.Fatalf("Read after EOF = (%d, %v), want (0, io.EOF)", endN, endErr)
			}
		})
	}
}

func TestOwnedFileReaderCloseIsIdempotentAndClosesInput(t *testing.T) {
	t.Parallel()
	file := openOwnedTestFile(t, []byte("data"))
	reader, err := NewOwnedFileReader(context.WithoutCancel(t.Context()), file)
	if err != nil {
		t.Fatal(err)
	}

	firstErr := reader.Close()
	secondErr := reader.Close()

	if firstErr != nil || secondErr != nil {
		t.Fatalf("Close errors = (%v, %v), want idempotent nil results", firstErr, secondErr)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("owned input Stat after Close = %v, want os.ErrClosed", err)
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = (%d, %v), want (0, os.ErrClosed)", n, err)
	}
}

func TestOwnedFileReaderCancellationReleasesEnteredRead(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancelCause(t.Context())
	reader, input, writer, entered := newEnteredOwnedFileReader(ctx, t)
	readDone := make(chan ownedReadResult, 1)
	go func() {
		n, err := reader.Read(make([]byte, 1))
		readDone <- ownedReadResult{err: err, n: n}
	}()
	waitForSignal(t, entered, "owned reader did not enter its delegated Read")

	cancel(errOwnedFileCanceled)
	var result ownedReadResult
	select {
	case result = <-readDone:
	case <-time.After(2 * time.Second):
		_ = writer.Close() //nolint:errcheck // release the delegated pipe read before failing
		_ = reader.Close() //nolint:errcheck // best effort after a test timeout
		select {
		case <-readDone:
		case <-time.After(5 * time.Second):
			t.Fatal("entered delegated Read remained blocked after cleanup")
		}
		t.Fatal("cancellation did not release an entered delegated Read")
	}
	if result.n != 0 || !errors.Is(result.err, errOwnedFileCanceled) {
		t.Fatalf("canceled entered Read = (%d, %v), want (0, cancellation cause)", result.n, result.err)
	}
	waitUntil(t, func() bool {
		_, err := input.Stat()
		return errors.Is(err, os.ErrClosed)
	}, "cancellation left the entered reader's owned input open")
}

func TestOwnedFileReaderCloseReleasesEnteredRead(t *testing.T) {
	t.Parallel()
	reader, input, writer, entered := newEnteredOwnedFileReader(context.WithoutCancel(t.Context()), t)
	readDone := make(chan ownedReadResult, 1)
	go func() {
		n, err := reader.Read(make([]byte, 1))
		readDone <- ownedReadResult{err: err, n: n}
	}()
	waitForSignal(t, entered, "owned reader did not enter its delegated Read")

	if err := reader.Close(); err != nil {
		t.Fatalf("Close entered reader: %v", err)
	}
	select {
	case result := <-readDone:
		if result.n != 0 || result.err == nil {
			t.Fatalf("entered Read released by Close = (%d, %v), want (0, non-nil error)", result.n, result.err)
		}
	case <-time.After(2 * time.Second):
		_ = writer.Close() //nolint:errcheck // release the delegated pipe read before failing
		select {
		case <-readDone:
		case <-time.After(5 * time.Second):
			t.Fatal("entered delegated Read remained blocked after cleanup")
		}
		t.Fatal("Close did not release an entered delegated Read")
	}
	if _, err := input.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("entered reader input Stat after Close = %v, want os.ErrClosed", err)
	}
}

type ownedReadResult struct {
	err error
	n   int
}

type enteredFileReader struct {
	file    *os.File
	entered chan struct{}
	once    sync.Once
}

func (reader *enteredFileReader) Read(buffer []byte) (int, error) {
	reader.once.Do(func() { close(reader.entered) })
	return reader.file.Read(buffer) //nolint:wrapcheck // expose the owned file's result to the wrapper
}

func newEnteredOwnedFileReader(
	ctx context.Context,
	t *testing.T,
) (*ownedFileReader, *os.File, *os.File, <-chan struct{}) {
	t.Helper()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	reader := &ownedFileReader{
		ctx:    ctx,
		file:   input,
		reader: &enteredFileReader{file: input, entered: entered},
		done:   make(chan struct{}),
	}
	if ctx != nil && ctx.Done() != nil {
		go reader.closeOnCancellation()
	}
	t.Cleanup(func() {
		_ = writer.Close() //nolint:errcheck // test cleanup is best effort
		_ = reader.Close() //nolint:errcheck // test cleanup is best effort
	})
	return reader, input, writer, entered
}

func openOwnedTestFile(t *testing.T, content []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() }) //nolint:errcheck // ownership tests may already have closed it
	return file
}
