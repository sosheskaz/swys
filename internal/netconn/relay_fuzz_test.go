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

const (
	maxFuzzRelayPayloadSize = 8 << 10
	// fuzzRelayHalfCloseWait turns a missing CloseWrite into a fast, named
	// failure instead of a hang that only the package test timeout catches.
	fuzzRelayHalfCloseWait = 5 * time.Second
)

var (
	errFuzzRelayInput            = errors.New("fuzz relay input failure")
	errFuzzRelayHalfCloseMissing = errors.New("fuzz relay peer was never half closed")
)

func FuzzRelayPreservesBidirectionalBytes(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1), false)
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1), true)
	f.Add([]byte("request"), []byte("response"), uint8(3), uint8(5), false)
	f.Add([]byte("request"), []byte("response"), uint8(3), uint8(5), true)
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255), false)
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255), true)

	f.Fuzz(func(t *testing.T, input, peer []byte, inputChunk, peerChunk uint8, closeWrite bool) {
		if len(input) > maxFuzzRelayPayloadSize || len(peer) > maxFuzzRelayPayloadSize {
			t.Skip()
		}

		// Relay races both directions, and only the input-first ordering reaches
		// the half-close decision. Holding the peer direction open until
		// CloseWrite forces that ordering instead of leaving it to the scheduler.
		connection := newFuzzStreamConn(peer, peerChunk, closeWrite)
		var output bytes.Buffer
		err := RelayWithOptions(
			t.Context(),
			connection,
			newFuzzChunkReader(input, inputChunk),
			&output,
			RelayOptions{CloseWrite: closeWrite, Duplex: true},
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
		wantCloseWrites := 0
		if closeWrite {
			wantCloseWrites = 1
		}
		if connection.closeWrites != wantCloseWrites {
			t.Fatalf("connection CloseWrite count = %d, want %d for closeWrite %t", connection.closeWrites, wantCloseWrites, closeWrite)
		}
	})
}

func FuzzRelayPreservesPrefixesBeforeInputFailure(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1), false)
	f.Add([]byte{}, []byte{}, uint8(1), uint8(1), true)
	f.Add([]byte("partial request"), []byte("response"), uint8(3), uint8(5), false)
	f.Add([]byte("partial request"), []byte("response"), uint8(3), uint8(5), true)
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255), false)
	f.Add([]byte{0x00, 0xff, 0x80}, []byte{0xfe, 0x00, 0x7f}, uint8(255), uint8(255), true)

	f.Fuzz(func(t *testing.T, input, peer []byte, inputChunk, peerChunk uint8, closeWrite bool) {
		if len(input) > maxFuzzRelayPayloadSize || len(peer) > maxFuzzRelayPayloadSize {
			t.Skip()
		}

		// A failed input copy returns before the half-close decision, so the peer
		// direction must not be gated on CloseWrite here.
		connection := newFuzzStreamConn(peer, peerChunk, false)
		var output bytes.Buffer
		inputWithFailure := io.MultiReader(
			newFuzzChunkReader(input, inputChunk),
			iotest.ErrReader(errFuzzRelayInput),
		)
		err := RelayWithOptions(
			t.Context(),
			connection,
			inputWithFailure,
			&output,
			RelayOptions{CloseWrite: closeWrite, Duplex: true},
		)
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
			t.Fatalf("connection CloseWrite count = %d, want 0 after input failure with closeWrite %t", connection.closeWrites, closeWrite)
		}
	})
}

func FuzzRelayReceiveOnlyPreservesBytes(f *testing.F) {
	f.Add([]byte{}, uint8(1))
	f.Add([]byte("response"), uint8(3))
	f.Add([]byte{0x00, 0xff, 0x80, 0x7f}, uint8(255))

	f.Fuzz(func(t *testing.T, peer []byte, peerChunk uint8) {
		if len(peer) > maxFuzzRelayPayloadSize {
			t.Skip()
		}

		connection := newFuzzStreamConn(peer, peerChunk, false)
		var output bytes.Buffer
		err := RelayWithOptions(
			t.Context(),
			connection,
			iotest.ErrReader(errFuzzRelayInput),
			&output,
			RelayOptions{ReceiveOnly: true},
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(output.Bytes(), peer) {
			t.Fatalf("received bytes changed: got %x, want %x", output.Bytes(), peer)
		}
		if connection.sent.Len() != 0 {
			t.Fatalf("sent bytes = %x, want none", connection.sent.Bytes())
		}
		if connection.closes != 1 {
			t.Fatalf("connection close count = %d, want 1", connection.closes)
		}
		if connection.closeWrites != 0 {
			t.Fatalf("connection CloseWrite count = %d, want 0", connection.closeWrites)
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
	peer *fuzzChunkReader
	// halfClosed, when non-nil, keeps the peer direction from reporting EOF
	// until CloseWrite runs. Only CloseWrite closes it, so a relay that never
	// half closes cannot finish this fixture.
	halfClosed  chan struct{}
	sent        bytes.Buffer
	closes      int
	closeWrites int
}

func newFuzzStreamConn(peer []byte, chunk uint8, awaitHalfClose bool) *fuzzStreamConn {
	connection := &fuzzStreamConn{peer: newFuzzChunkReader(peer, chunk)}
	if awaitHalfClose {
		connection.halfClosed = make(chan struct{})
	}
	return connection
}

func (connection *fuzzStreamConn) Read(buffer []byte) (int, error) {
	read, err := connection.peer.Read(buffer)
	if connection.halfClosed == nil || !errors.Is(err, io.EOF) {
		return read, err
	}
	timer := time.NewTimer(fuzzRelayHalfCloseWait)
	defer timer.Stop()
	select {
	case <-connection.halfClosed:
		return read, err
	case <-timer.C:
		return read, errFuzzRelayHalfCloseMissing
	}
}

func (connection *fuzzStreamConn) Write(buffer []byte) (int, error) {
	written, err := connection.sent.Write(buffer)
	return written, err //nolint:wrapcheck // preserve io.Writer error identity in the relay fixture
}

func (connection *fuzzStreamConn) Close() error {
	connection.closes++
	return nil
}

// CloseWrite runs on Relay's own goroutine, so closeWrites needs no
// synchronization; the channel is what the peer goroutine observes.
func (connection *fuzzStreamConn) CloseWrite() error {
	connection.closeWrites++
	if connection.halfClosed != nil && connection.closeWrites == 1 {
		close(connection.halfClosed)
	}
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
