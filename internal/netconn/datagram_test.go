package netconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

var (
	errUDPTestInput   = errors.New("UDP input failed")
	errUDPTestRequest = errors.New("unexpected UDP request")
)

func TestReadDatagramPreservesMaximumPortableUDPPayload(t *testing.T) {
	t.Parallel()

	want := bytes.Repeat([]byte{0xa5}, MaxUDPPayloadSize)
	got, err := ReadDatagram(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("datagram length = %d, want %d exact bytes", len(got), len(want))
	}
}

func TestReadDatagramRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	_, err := ReadDatagram(bytes.NewReader(make([]byte, MaxUDPPayloadSize+1)))
	if !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("error = %v, want ErrDatagramTooLarge", err)
	}
}

func TestReadDatagramReturnsInputFailure(t *testing.T) {
	t.Parallel()

	want := errUDPTestInput
	_, err := ReadDatagram(iotest.ErrReader(want))
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want input failure", err)
	}
}

func TestReadDatagramContextCancellationDoesNotCloseInput(t *testing.T) {
	t.Parallel()

	input, writer := io.Pipe()
	t.Cleanup(func() {
		if err := input.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close datagram input: %v", err)
		}
		if err := writer.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close datagram writer: %v", err)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := ReadDatagramContext(ctx, input)
		done <- err
	}()

	if _, err := writer.Write([]byte("partial")); err != nil {
		t.Fatalf("start blocked datagram input read: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("datagram input read did not stop waiting after cancellation")
	}
	if _, err := writer.Write([]byte("still open")); err != nil {
		t.Fatalf("input was closed by cancellation: %v", err)
	}
}

func TestReadDatagramContextRejectsCanceledContextBeforeRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ReadDatagramContext(ctx, iotest.ErrReader(errUDPTestInput))
	if !errors.Is(err, context.Canceled) || errors.Is(err, errUDPTestInput) {
		t.Fatalf("error = %v, want context cancellation before input read", err)
	}
}

func TestDialUDPExchangesOneDatagramOnLoopback(t *testing.T) {
	t.Parallel()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })

	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		read, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		if string(buffer[:read]) != "request" {
			serverDone <- errUDPTestRequest
			return
		}
		_, writeErr := listener.WriteToUDP([]byte("response"), peer)
		serverDone <- writeErr
	}()

	connection, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, connection) })
	if err := SendUDP(t.Context(), connection, []byte("request")); err != nil {
		t.Fatal(err)
	}
	response, err := ReceiveUDP(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q, want response", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialUDPRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	connection, err := DialUDP(ctx, "127.0.0.1:53")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if connection != nil {
		closeTestUDPConnection(t, connection)
		t.Fatal("DialUDP returned a connection for a canceled context")
	}
}

func TestSendUDPTransmitsZeroLengthDatagram(t *testing.T) {
	t.Parallel()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	connection, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, connection) })

	if err := SendUDP(t.Context(), connection, nil); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	read, _, err := listener.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if read != 0 {
		t.Fatalf("received length = %d, want zero-length datagram", read)
	}
}

func TestReceiveUDPCancellation(t *testing.T) {
	t.Parallel()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	connection, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, connection) })

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, err = ReceiveUDP(ctx, connection)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}
}

func TestSendUDPRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	connection := &net.UDPConn{}
	err := SendUDP(t.Context(), connection, make([]byte, MaxUDPPayloadSize+1))
	if !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("error = %v, want ErrDatagramTooLarge", err)
	}
}

func TestReceiveUDPRejectsCanceledContextBeforeIO(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ReceiveUDP(ctx, &net.UDPConn{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestUDPOperationRecognizesDeadlineWhileCancellationPropagates(t *testing.T) {
	t.Parallel()

	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, connection) })
	ctx := newLaggedDeadlineContext(t.Context(), time.Now().Add(-time.Second))
	processed, err := udpOperation(ctx, connection, func() (int, error) {
		return connection.Read(make([]byte, 1))
	})
	if processed != 0 {
		t.Fatalf("processed = %d, want no datagram bytes", processed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want propagated context deadline", err)
	}
}

type laggedDeadlineContext struct {
	deadline   time.Time
	done       chan struct{}
	propagate  chan struct{}
	value      func(any) any
	errChecks  atomic.Int32
	propagated atomic.Bool
}

func newLaggedDeadlineContext(parent context.Context, deadline time.Time) *laggedDeadlineContext {
	ctx := &laggedDeadlineContext{
		deadline:  deadline,
		done:      make(chan struct{}),
		propagate: make(chan struct{}),
		value:     parent.Value,
	}
	go func() {
		select {
		case <-ctx.propagate:
			ctx.propagated.Store(true)
			close(ctx.done)
		case <-parent.Done():
		}
	}()
	return ctx
}

func (ctx *laggedDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func (ctx *laggedDeadlineContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *laggedDeadlineContext) Err() error {
	if ctx.propagated.Load() {
		return context.DeadlineExceeded
	}
	if ctx.errChecks.Add(1) == 2 {
		close(ctx.propagate)
	}
	return nil
}

func (ctx *laggedDeadlineContext) Value(key any) any {
	return ctx.value(key)
}

func closeTestUDPConnection(t *testing.T, connection io.Closer) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close UDP connection: %v", err)
	}
}
