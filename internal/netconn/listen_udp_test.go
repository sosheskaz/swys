package netconn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestListenUDPReceivesAndRespondsOnLoopback(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	if err := SendUDP(t.Context(), client, []byte("request")); err != nil {
		t.Fatal(err)
	}
	request, peer, err := ReceiveUDPFrom(t.Context(), listener)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q, want request", request)
	}
	if err := SendUDPTo(t.Context(), listener, []byte("response"), peer); err != nil {
		t.Fatal(err)
	}
	response, err := ReceiveUDP(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q, want response", response)
	}
}

func TestListenUDPRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	listener, err := ListenUDP(ctx, "127.0.0.1:0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if listener != nil {
		closeTestUDPConnection(t, listener)
		t.Fatal("ListenUDP returned a socket for a canceled context")
	}
}

func TestReceiveUDPFromCancellationClearsDeadline(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, _, err = ReceiveUDPFrom(ctx, listener)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}

	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	if err := SendUDP(t.Context(), client, []byte("after timeout")); err != nil {
		t.Fatal(err)
	}
	payload, _, err := ReceiveUDPFrom(t.Context(), listener)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "after timeout" {
		t.Fatalf("payload = %q, want socket reuse after timeout", payload)
	}
}

func TestListenUDPBindFailure(t *testing.T) {
	t.Parallel()

	first, err := ListenUDP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, first) })
	second, err := ListenUDP(t.Context(), first.LocalAddr().String())
	if err == nil {
		closeTestUDPConnection(t, second)
		t.Fatal("second UDP bind unexpectedly succeeded")
	}
}

func TestSendUDPToTransmitsZeroLengthDatagram(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	if err := SendUDP(t.Context(), client, []byte("request")); err != nil {
		t.Fatal(err)
	}
	_, peer, err := ReceiveUDPFrom(t.Context(), listener)
	if err != nil {
		t.Fatal(err)
	}
	if err := SendUDPTo(t.Context(), listener, nil, peer); err != nil {
		t.Fatal(err)
	}
	response, err := ReceiveUDP(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 0 {
		t.Fatalf("response length = %d, want zero", len(response))
	}
}

func TestSendUDPToRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	err := SendUDPTo(
		t.Context(),
		&net.UDPConn{},
		make([]byte, MaxUDPPayloadSize+1),
		&net.UDPAddr{},
	)
	if !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("error = %v, want ErrDatagramTooLarge", err)
	}
}
