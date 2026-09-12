package netconn

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

const maxFuzzDatagramPayloadSize = 4 << 10

var errFuzzDatagramInput = errors.New("fuzz datagram input failure")

func FuzzReadDatagram(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x80, 0x0a})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > maxFuzzDatagramPayloadSize {
			t.Skip()
		}

		readers := []io.Reader{bytes.NewReader(payload)}
		if len(payload) <= 512 {
			readers = append(readers, iotest.OneByteReader(bytes.NewReader(payload)))
		}
		for _, reader := range readers {
			got, err := ReadDatagram(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("datagram bytes changed: got %x, want %x", got, payload)
			}
		}
	})
}

func FuzzReadDatagramInputFailure(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x80, 0x0a})

	f.Fuzz(func(t *testing.T, prefix []byte) {
		if len(prefix) > maxFuzzDatagramPayloadSize {
			t.Skip()
		}

		input := io.MultiReader(bytes.NewReader(prefix), iotest.ErrReader(errFuzzDatagramInput))
		payload, err := ReadDatagram(input)
		if payload != nil {
			t.Fatalf("payload = %x, want nil after input failure", payload)
		}
		if !errors.Is(err, errFuzzDatagramInput) {
			t.Fatalf("error = %v, want input failure", err)
		}
	})
}
