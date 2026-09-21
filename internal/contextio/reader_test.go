package contextio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

type readerKind struct {
	// open returns the wrapped reader and how many source bytes it has consumed.
	open func(ctx context.Context, t *testing.T, content []byte) (io.Reader, func() int)
	name string
}

func readerKinds() []readerKind {
	return []readerKind{
		{name: "regular file", open: openFileReader},
		{name: "memory", open: openMemoryReader},
		{name: "pipe", open: openPipeReader},
	}
}

func openFileReader(ctx context.Context, t *testing.T, content []byte) (io.Reader, func() int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() }) //nolint:errcheck // test cleanup is best effort
	reader := NewReader(ctx, file)
	if _, ok := reader.(*checkedReader); !ok {
		t.Fatalf("regular file wrapped as %T, want a reader that never starts a goroutine", reader)
	}
	return reader, func() int {
		offset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatal(err)
		}
		return int(offset)
	}
}

func openMemoryReader(ctx context.Context, t *testing.T, content []byte) (io.Reader, func() int) {
	t.Helper()
	source := &recordingReader{reader: bytes.NewReader(content)}
	return NewReader(ctx, source), func() int { return source.consumed }
}

func openPipeReader(ctx context.Context, t *testing.T, content []byte) (io.Reader, func() int) {
	t.Helper()
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		_, err := pipeWriter.Write(content)
		pipeWriter.CloseWithError(err)
	}()
	t.Cleanup(func() { _ = pipeReader.Close() }) //nolint:errcheck // test cleanup is best effort
	source := &recordingReader{reader: pipeReader}
	return NewReader(ctx, source), func() int { return source.consumed }
}

// recordingReader tracks the source-side traffic that the wrapper causes.
type recordingReader struct {
	reader   io.Reader
	consumed int
	reads    int
	largest  int
}

func (reader *recordingReader) Read(buffer []byte) (int, error) {
	reader.reads++
	reader.largest = max(reader.largest, len(buffer))
	n, err := reader.reader.Read(buffer)
	reader.consumed += n
	return n, err //nolint:wrapcheck // preserve the wrapped reader's stream semantics
}

func TestReaderPassesThroughWhenNeverCanceled(t *testing.T) {
	t.Parallel()
	source := strings.NewReader("input")
	var noContext context.Context

	for name, ctx := range map[string]context.Context{
		"context that cannot be canceled": context.WithoutCancel(t.Context()),
		"missing context":                 noContext,
	} {
		if got := NewReader(ctx, source); got != io.Reader(source) {
			t.Fatalf("%s: reader = %T, want the source itself so Fd and WriteTo stay available", name, got)
		}
	}
}

func TestReaderDeliversSourceBytesUnchanged(t *testing.T) {
	t.Parallel()
	for _, kind := range readerKinds() {
		for _, size := range []int{0, 1, readChunk - 1, readChunk, readChunk + 1, 3*readChunk + 7} {
			t.Run(kind.name+"/"+strconv.Itoa(size), func(t *testing.T) {
				t.Parallel()
				content := make([]byte, size)
				for i := range content {
					content[i] = byte(i % 251)
				}
				reader, _ := kind.open(t.Context(), t, content)
				if err := iotest.TestReader(reader, content); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReaderRefusesReadsAfterCancellation(t *testing.T) {
	t.Parallel()
	for _, kind := range readerKinds() {
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancelCause(t.Context())
			reader, consumed := kind.open(ctx, t, []byte("data"))
			cancel(errCause)

			n, err := reader.Read(make([]byte, 4))

			if n != 0 || !errors.Is(err, errCause) {
				t.Fatalf("Read = (%d, %v), want (0, cancellation cause)", n, err)
			}
			if got := consumed(); got != 0 {
				t.Fatalf("source consumed %d bytes after cancellation, want 0", got)
			}
		})
	}
}

func TestReaderStopsAfterDeliveredData(t *testing.T) {
	t.Parallel()
	for _, kind := range readerKinds() {
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancelCause(t.Context())
			reader, _ := kind.open(ctx, t, []byte("abcdef"))
			buffer := make([]byte, 3)
			if n, err := reader.Read(buffer); err != nil || string(buffer[:n]) != "abc"[:n] {
				t.Fatalf("first Read = (%q, %v), want leading bytes", buffer[:n], err)
			}

			cancel(errCause)

			if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, errCause) {
				t.Fatalf("Read after cancellation = (%d, %v), want (0, cancellation cause)", n, err)
			}
		})
	}
}

func TestReaderReleasesBlockedRead(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancelCause(t.Context())
	source := newGatedReader("late bytes")
	reader := NewReader(ctx, source)
	buffer := make([]byte, 16)
	result := make(chan error, 1)
	go func() {
		_, err := reader.Read(buffer)
		result <- err
	}()
	waitForSignal(t, source.entered, "source read did not start")

	cancel(errCause)

	select {
	case err := <-result:
		if !errors.Is(err, errCause) {
			t.Fatalf("Read error = %v, want cancellation cause", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read stayed blocked after cancellation")
	}
	// The abandoned source read completes later; it must not reach the caller.
	close(source.release)
	waitForSignal(t, source.finished, "source read did not finish")
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatalf("abandoned read wrote %q into the caller's buffer", buffer)
	}
}

func TestReaderReadsOnlyWhatTheCallerRequests(t *testing.T) {
	t.Parallel()
	source := &recordingReader{reader: bytes.NewReader(make([]byte, 4*readChunk))}
	reader := NewReader(t.Context(), source)

	if _, err := reader.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if source.largest != 10 {
		t.Fatalf("source asked for %d bytes, want 10 so unrequested bytes stay in the source", source.largest)
	}

	if _, err := reader.Read(make([]byte, 3*readChunk)); err != nil {
		t.Fatal(err)
	}
	if source.largest != readChunk {
		t.Fatalf("source asked for %d bytes, want the %d-byte chunk cap", source.largest, readChunk)
	}
}

func TestReaderPreservesSourceErrors(t *testing.T) {
	t.Parallel()

	t.Run("blocking reader reports data before the error and then stays failed", func(t *testing.T) {
		t.Parallel()
		source := &recordingReader{reader: io.MultiReader(strings.NewReader("ab"), iotest.ErrReader(errCause))}
		reader := NewReader(t.Context(), source)

		got, err := io.ReadAll(reader)
		if string(got) != "ab" || !errors.Is(err, errCause) {
			t.Fatalf("ReadAll = (%q, %v), want data then the source error", got, err)
		}
		reads := source.reads
		if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, errCause) {
			t.Fatalf("Read after failure = %v, want the same source error", err)
		}
		if source.reads != reads {
			t.Fatal("a failed reader consulted the source again")
		}
	})

	t.Run("regular file errors pass through", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		reader := NewReader(t.Context(), file)
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := reader.Read(make([]byte, 4)); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read error = %v, want the file's closed error", err)
		}
	})
}

func TestReaderZeroLengthReadLeavesSourceAlone(t *testing.T) {
	t.Parallel()
	source := &recordingReader{reader: strings.NewReader("data")}
	reader := NewReader(t.Context(), source)

	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if source.reads != 0 {
		t.Fatalf("zero-length read reached the source %d times", source.reads)
	}
}

// gatedReader blocks its first Read until released, then yields its bytes.
type gatedReader struct {
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
	data     string
	once     sync.Once
}

func newGatedReader(data string) *gatedReader {
	return &gatedReader{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
		data:     data,
	}
}

func (reader *gatedReader) Read(buffer []byte) (int, error) {
	reader.once.Do(func() { close(reader.entered) })
	<-reader.release
	defer close(reader.finished)
	return copy(buffer, reader.data), io.EOF
}

func BenchmarkReader(b *testing.B) {
	content := bytes.Repeat([]byte{0xa5}, 1<<20)
	buffer := make([]byte, readChunk)
	drain := func(b *testing.B, reader io.Reader) {
		b.Helper()
		for {
			_, err := reader.Read(buffer)
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				b.Fatal(err)
			}
		}
	}

	b.Run("bare memory reader", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(content)))
		for b.Loop() {
			drain(b, bytes.NewReader(content))
		}
	})
	openFile := func(b *testing.B) *os.File {
		b.Helper()
		path := filepath.Join(b.TempDir(), "input")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			b.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = file.Close() }) //nolint:errcheck // benchmark cleanup is best effort
		return file
	}
	for name, wrap := range map[string]func(*os.File) io.Reader{
		"bare regular file":    func(file *os.File) io.Reader { return file },
		"checked regular file": func(file *os.File) io.Reader { return NewReader(b.Context(), file) },
	} {
		b.Run(name, func(b *testing.B) {
			file := openFile(b)
			reader := wrap(file)
			b.ReportAllocs()
			b.SetBytes(int64(len(content)))
			for b.Loop() {
				if _, err := file.Seek(0, io.SeekStart); err != nil {
					b.Fatal(err)
				}
				drain(b, reader)
			}
		})
	}
	b.Run("blocking memory reader", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(content)))
		for b.Loop() {
			drain(b, NewReader(b.Context(), bytes.NewReader(content)))
		}
	})
}
