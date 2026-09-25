package artifact

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

const maxFuzzArtifactInputSize = 1 << 12

var errFuzzArtifactRead = errors.New("fuzz artifact read failure")

func FuzzReadArtifact(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add([]byte("exact"), uint16(5))
	f.Add([]byte("one byte too many"), uint16(16))
	f.Add(bytes.Repeat([]byte{0xff}, 257), uint16(256))

	f.Fuzz(func(t *testing.T, data []byte, fuzzLimit uint16) {
		if len(data) > maxFuzzArtifactInputSize {
			t.Skip()
		}
		limit := int64(fuzzLimit % 1025)

		for _, oneByte := range []bool{false, true} {
			input := bytes.NewReader(data)
			var reader io.Reader = input
			if oneByte {
				reader = iotest.OneByteReader(reader)
			}
			got, err := Read(reader, limit)
			consumed := min(len(data), int(limit)+1)
			if remaining := input.Len(); remaining != len(data)-consumed {
				t.Fatalf("reader retained %d bytes, want %d", remaining, len(data)-consumed)
			}
			if int64(len(data)) > limit {
				if !errors.Is(err, ErrTooLarge) || got != nil {
					t.Fatalf("oversized artifact = %x, %v", got, err)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("artifact bytes changed: got %x, want %x", got, data)
			}
		}

		failAfter := int(fuzzLimit) % (len(data) + 1)
		for _, oneByte := range []bool{false, true} {
			failing := &fuzzArtifactFailingReader{data: data, failAfter: failAfter}
			var reader io.Reader = failing
			if oneByte {
				reader = iotest.OneByteReader(reader)
			}
			got, err := Read(reader, int64(len(data)))
			if !errors.Is(err, errFuzzArtifactRead) || got != nil {
				t.Fatalf("failed artifact read = %x, %v", got, err)
			}
		}
	})
}

type fuzzArtifactFailingReader struct {
	data      []byte
	position  int
	failAfter int
}

func (reader *fuzzArtifactFailingReader) Read(buffer []byte) (int, error) {
	if reader.position >= reader.failAfter {
		return 0, errFuzzArtifactRead
	}
	end := min(reader.failAfter, reader.position+len(buffer))
	read := copy(buffer, reader.data[reader.position:end])
	reader.position += read
	if reader.position == reader.failAfter {
		return read, errFuzzArtifactRead
	}
	return read, nil
}
