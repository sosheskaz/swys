package contextio

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

const (
	maxFuzzReaderPayloadSize = 8 << 10
	// fuzzReaderLargeBuffer exceeds readChunk so every payload also crosses
	// the wrapper's chunk cap, not just the small generated buffer sizes.
	fuzzReaderLargeBuffer = readChunk + 7
)

var errFuzzReaderSource = errors.New("fuzz reader source failure")

// FuzzReaderPreservesStreamBytes drives the blocking wrapper — the path every
// non-file input (stdin, sockets, pipes) takes — across generated source chunk
// sizes and caller buffer sizes, including one larger than the internal
// readChunk cap. The source must be relayed byte for byte, EOF must arrive
// exactly once as the terminal error, and the helper goroutine must never ask
// the source for more than the caller requested (or readChunk, whichever is
// smaller). Zero-length reads must not reach the source.
func FuzzReaderPreservesStreamBytes(f *testing.F) {
	f.Add([]byte{}, uint8(1), uint8(1))
	f.Add([]byte("input"), uint8(3), uint8(5))
	f.Add([]byte{0x00, 0xff, 0x80, 0x7f}, uint8(255), uint8(255))
	f.Add(bytes.Repeat([]byte{0xa5}, 300), uint8(7), uint8(64))
	f.Add([]byte("line\nwith\r\ncontrols\x00\x1b"), uint8(2), uint8(9))

	f.Fuzz(func(t *testing.T, payload []byte, sourceChunk, bufferChunk uint8) {
		if len(payload) > maxFuzzReaderPayloadSize {
			t.Skip()
		}

		for _, size := range []int{int(bufferChunk%64) + 1, fuzzReaderLargeBuffer} {
			source := &recordingReader{reader: newFuzzChunkReader(payload, sourceChunk)}
			reader := NewReader(t.Context(), source)

			if n, err := reader.Read(nil); n != 0 || err != nil {
				t.Fatalf("zero-length Read = (%d, %v), want (0, nil)", n, err)
			}
			if source.reads != 0 {
				t.Fatalf("zero-length Read performed %d source reads, want none", source.reads)
			}

			var received bytes.Buffer
			var terminal error
			buffer := make([]byte, size)
			for {
				n, err := reader.Read(buffer)
				received.Write(buffer[:n])
				if err != nil {
					terminal = err
					break
				}
				if n == 0 {
					t.Fatal("Read returned (0, nil) before EOF")
				}
			}
			if !errors.Is(terminal, io.EOF) {
				t.Fatalf("terminal Read error = %v, want io.EOF", terminal)
			}
			if !bytes.Equal(received.Bytes(), payload) {
				t.Fatalf("relayed bytes changed: got %x, want %x", received.Bytes(), payload)
			}
			if source.consumed != len(payload) {
				t.Fatalf("source consumed %d bytes, want %d", source.consumed, len(payload))
			}
			if source.largest > min(size, readChunk) {
				t.Fatalf("largest source read = %d, want at most min(%d, %d)", source.largest, size, readChunk)
			}

			reads := source.reads
			if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("Read after EOF = (%d, %v), want sticky (0, io.EOF)", n, err)
			}
			if source.reads != reads {
				t.Fatal("Read after EOF consulted the source again")
			}
		}
	})
}

// FuzzReaderPreservesPrefixesBeforeSourceFailure feeds the blocking wrapper a
// source that fails partway, both as data-then-error and as data-and-error in
// a single Read. Bytes delivered before the failure must survive exactly, the
// source error must keep its identity, and the wrapper must stay failed
// without consulting the source again.
func FuzzReaderPreservesPrefixesBeforeSourceFailure(f *testing.F) {
	f.Add([]byte{}, uint8(1), uint8(1), uint16(0))
	f.Add([]byte("partial payload"), uint8(3), uint8(5), uint16(7))
	f.Add([]byte("delivered with failure"), uint8(4), uint8(64), uint16(22))
	f.Add([]byte{0x00, 0xff, 0x80, 0x7f}, uint8(255), uint8(255), uint16(2))

	f.Fuzz(func(t *testing.T, payload []byte, sourceChunk, bufferChunk uint8, failAfter uint16) {
		if len(payload) > maxFuzzReaderPayloadSize {
			t.Skip()
		}
		cut := int(failAfter) % (len(payload) + 1)

		for _, size := range []int{int(bufferChunk%64) + 1, fuzzReaderLargeBuffer} {
			// Shape one: the source delivers the whole payload, then fails.
			appended := &recordingReader{reader: io.MultiReader(
				newFuzzChunkReader(payload, sourceChunk),
				iotest.ErrReader(errFuzzReaderSource),
			)}
			drainFuzzReaderFailure(t, NewReader(t.Context(), appended), appended, payload, size)

			// Shape two: the source returns data and the failure together once
			// the prefix is exhausted.
			combined := &recordingReader{reader: &fuzzFailingReader{
				data:      payload,
				failAfter: cut,
			}}
			drainFuzzReaderFailure(t, NewReader(t.Context(), combined), combined, payload[:cut], size)
		}
	})
}

func drainFuzzReaderFailure(t *testing.T, reader io.Reader, source *recordingReader, prefix []byte, size int) {
	t.Helper()
	var received bytes.Buffer
	var terminal error
	buffer := make([]byte, size)
	for {
		n, err := reader.Read(buffer)
		received.Write(buffer[:n])
		if err != nil {
			terminal = err
			break
		}
		if n == 0 {
			t.Fatal("Read returned (0, nil) while the source still had bytes")
		}
	}
	if !errors.Is(terminal, errFuzzReaderSource) {
		t.Fatalf("terminal Read error = %v, want the source failure", terminal)
	}
	if !bytes.Equal(received.Bytes(), prefix) {
		t.Fatalf("prefix before failure changed: got %x, want %x", received.Bytes(), prefix)
	}
	if source.consumed != len(prefix) {
		t.Fatalf("source consumed %d bytes, want %d", source.consumed, len(prefix))
	}

	reads := source.reads
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, errFuzzReaderSource) {
		t.Fatalf("Read after failure = (%d, %v), want sticky (0, source failure)", n, err)
	}
	if source.reads != reads {
		t.Fatal("failed reader consulted the source again")
	}
}

// fuzzChunkReader limits each source Read to a generated chunk so the wrapper
// relays arbitrary source fragmentation.
type fuzzChunkReader struct {
	source  *bytes.Reader
	maximum int
}

func newFuzzChunkReader(data []byte, chunk uint8) *fuzzChunkReader {
	return &fuzzChunkReader{source: bytes.NewReader(data), maximum: int(chunk%64) + 1}
}

func (reader *fuzzChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		buffer = buffer[:reader.maximum]
	}
	read, err := reader.source.Read(buffer)
	return read, err //nolint:wrapcheck // preserve io.Reader error identity in the fuzz fixture
}

// fuzzFailingReader returns the prefix and then (data and) the failure in one
// Read, the way OS-level reads can deliver bytes and an error together.
type fuzzFailingReader struct {
	data      []byte
	failAfter int
	position  int
}

func (reader *fuzzFailingReader) Read(buffer []byte) (int, error) {
	if reader.position >= reader.failAfter {
		return 0, errFuzzReaderSource
	}
	end := min(reader.failAfter, reader.position+len(buffer))
	read := copy(buffer, reader.data[reader.position:end])
	reader.position += read
	if reader.position == reader.failAfter {
		return read, errFuzzReaderSource
	}
	return read, nil
}
