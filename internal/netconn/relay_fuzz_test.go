package netconn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"
)

const maxFuzzRelayPayloadSize = 8 << 10

var errFuzzRelayInput = errors.New("fuzz relay input failure")

func FuzzRelayPreservesBidirectionalBytesWithoutHalfClose(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1))
	f.Add([]byte("request"), []byte("response"), uint8(3), uint8(5))
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255))

	f.Fuzz(func(t *testing.T, input, peer []byte, inputChunk, peerChunk uint8) {
		if len(input) > maxFuzzRelayPayloadSize || len(peer) > maxFuzzRelayPayloadSize {
			t.Skip()
		}

		connection := newFuzzStreamConn(peer, peerChunk)
		var output bytes.Buffer
		err := Relay(
			t.Context(),
			connection,
			newFuzzChunkReader(input, inputChunk),
			&output,
			0,
			false,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(connection.sent.Bytes(), input) {
			t.Fatalf("sent bytes changed: got %x, want %x", connection.sent.Bytes(), input)
		}
		if !bytes.Equal(output.Bytes(), peer) {
			t.Fatalf("received bytes changed: got %x, want %x", output.Bytes(), peer)
		}
		if connection.closes != 1 {
			t.Fatalf("connection close count = %d, want 1", connection.closes)
		}
		if connection.closeWrites != 0 {
			t.Fatalf("connection CloseWrite count = %d, want 0", connection.closeWrites)
		}
	})
}

func FuzzRelayPreservesPrefixesBeforeInputFailure(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1))
	f.Add([]byte("partial request"), []byte("response"), uint8(3), uint8(5))
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255))

	f.Fuzz(func(t *testing.T, input, peer []byte, inputChunk, peerChunk uint8) {
		if len(input) > maxFuzzRelayPayloadSize || len(peer) > maxFuzzRelayPayloadSize {
			t.Skip()
		}

		connection := newFuzzStreamConn(peer, peerChunk)
		var output bytes.Buffer
		inputWithFailure := io.MultiReader(
			newFuzzChunkReader(input, inputChunk),
			iotest.ErrReader(errFuzzRelayInput),
		)
		err := Relay(t.Context(), connection, inputWithFailure, &output, 0, true)
		if !errors.Is(err, errFuzzRelayInput) {
			t.Fatalf("error = %v, want input failure", err)
		}
		if !bytes.Equal(connection.sent.Bytes(), input) {
			t.Fatalf("sent prefix changed: got %x, want %x", connection.sent.Bytes(), input)
		}
		if !bytes.Equal(output.Bytes(), peer) {
			t.Fatalf("received bytes changed: got %x, want %x", output.Bytes(), peer)
		}
		if connection.closes != 1 {
			t.Fatalf("connection close count = %d, want 1", connection.closes)
		}
		if connection.closeWrites != 0 {
			t.Fatalf("connection CloseWrite count = %d, want 0 after input failure", connection.closeWrites)
		}
	})
}

type fuzzChunkReader struct {
	source  *bytes.Reader
	maximum int
}

func newFuzzChunkReader(data []byte, chunk uint8) *fuzzChunkReader {
	return &fuzzChunkReader{
		source:  bytes.NewReader(data),
		maximum: int(chunk%64) + 1,
	}
}

func (reader *fuzzChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		buffer = buffer[:reader.maximum]
	}
	read, err := reader.source.Read(buffer)
	return read, err //nolint:wrapcheck // preserve io.Reader error identity in the relay fixture
}

type fuzzStreamConn struct {
	peer        *fuzzChunkReader
	sent        bytes.Buffer
	closes      int
	closeWrites int
}

func newFuzzStreamConn(peer []byte, chunk uint8) *fuzzStreamConn {
	return &fuzzStreamConn{peer: newFuzzChunkReader(peer, chunk)}
}

func (connection *fuzzStreamConn) Read(buffer []byte) (int, error) {
	return connection.peer.Read(buffer)
}

func (connection *fuzzStreamConn) Write(buffer []byte) (int, error) {
	written, err := connection.sent.Write(buffer)
	return written, err //nolint:wrapcheck // preserve io.Writer error identity in the relay fixture
}

func (connection *fuzzStreamConn) Close() error {
	connection.closes++
	return nil
}

func (connection *fuzzStreamConn) CloseWrite() error {
	connection.closeWrites++
	return nil
}

func (connection *fuzzStreamConn) LocalAddr() net.Addr {
	return fuzzNetAddr("local")
}

func (connection *fuzzStreamConn) RemoteAddr() net.Addr {
	return fuzzNetAddr("remote")
}

func (connection *fuzzStreamConn) SetDeadline(time.Time) error {
	return nil
}

func (connection *fuzzStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

func (connection *fuzzStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

type fuzzNetAddr string

func (fuzzNetAddr) Network() string {
	return "fuzz"
}

func (address fuzzNetAddr) String() string {
	return string(address)
}
