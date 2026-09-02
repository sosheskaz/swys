package netconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

var (
	errUnexpectedRequest = errors.New("unexpected request")
	errTestInput         = errors.New("input failed")
	errTestOutput        = errors.New("output failed")
)

func TestRelayHalfClosesAndDrainsPeerResponse(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	serverErr := make(chan error, 1)
	go func() {
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(peer, request); err != nil {
			serverErr <- err
			return
		}
		if string(request) != "request" {
			serverErr <- errUnexpectedRequest
			return
		}
		<-client.writeClosed
		time.Sleep(20 * time.Millisecond)
		if _, err := io.WriteString(peer, "response"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- peer.Close()
	}()

	var output bytes.Buffer
	if err := Relay(t.Context(), client, strings.NewReader("request"), &output, time.Second, true); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "response" {
		t.Fatalf("response = %q, want %q", got, "response")
	}
}

func TestRelayDrainExpiryClosesSuccessfully(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		if _, err := io.ReadAll(peer); err != nil {
			peerDone <- err
			return
		}
		peerDone <- peer.Close()
	}()

	if err := Relay(t.Context(), client, strings.NewReader("request"), io.Discard, 20*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayZeroWaitDrainsUntilPeerEOF(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	serverErr := make(chan error, 1)
	go func() {
		<-client.writeClosed
		time.Sleep(30 * time.Millisecond)
		if _, err := io.WriteString(peer, "late response"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- peer.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := Relay(ctx, client, strings.NewReader(""), &output, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "late response" {
		t.Fatalf("response = %q, want %q", got, "late response")
	}
}

func TestRelayCancellationClosesConnection(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close peer connection: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	err := Relay(ctx, client, strings.NewReader(""), io.Discard, 0, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}

func TestRelayReturnsWhenPeerClosesBeforeInput(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	input, inputWriter := io.Pipe()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := Relay(ctx, client, input, io.Discard, time.Second, false); err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayClosesConnectionWhenInputFails(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(peer)
		peerDone <- errors.Join(err, peer.Close())
	}()

	err := Relay(t.Context(), client, iotest.ErrReader(errTestInput), io.Discard, time.Second, false)
	if !errors.Is(err, errTestInput) {
		t.Fatalf("error = %v, want input failure", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayReturnsOutputFailure(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		<-client.writeClosed
		_, err := io.WriteString(peer, "response")
		peerDone <- errors.Join(err, peer.Close())
	}()

	err := Relay(t.Context(), client, strings.NewReader(""), failingWriter{err: errTestOutput}, time.Second, true)
	if !errors.Is(err, errTestOutput) {
		t.Fatalf("error = %v, want output failure", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

type pipeStream struct {
	net.Conn
	writeClosed chan struct{}
	closeOnce   sync.Once
}

type failingWriter struct {
	err error
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func newPipeStream(t *testing.T) (*pipeStream, net.Conn) {
	t.Helper()
	client, peer := net.Pipe()
	return &pipeStream{Conn: client, writeClosed: make(chan struct{})}, peer
}

func (connection *pipeStream) CloseWrite() error {
	connection.closeOnce.Do(func() { close(connection.writeClosed) })
	return nil
}
