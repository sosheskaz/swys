package netconn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestListenAndAcceptTCPPortZero(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	listener, err := ListenTCP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := AcceptTCP(ctx, listener)
		accepted <- connection
		acceptErr <- err
	}()

	client, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestTCPConnection(t, client) })
	server := <-accepted
	if err := <-acceptErr; err != nil {
		t.Fatal(err)
	}
	if server == nil {
		t.Fatal("accepted connection is nil")
	}
	t.Cleanup(func() { closeTestTCPConnection(t, server) })
	if server.LocalAddr().String() != address {
		t.Fatalf("accepted local address = %q, want %q", server.LocalAddr(), address)
	}

	second, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
	if err == nil {
		closeTestTCPConnection(t, second)
		t.Fatal("listener accepted a second connection")
	}
}

func TestAcceptTCPCancellationClosesListener(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	accepted := make(chan error, 1)
	go func() {
		_, err := AcceptTCP(ctx, listener)
		accepted <- err
	}()
	cancel()
	err = <-accepted
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if !strings.Contains(err.Error(), "accept TCP connection on "+`"`+address+`"`) {
		t.Fatalf("error = %v, want named accept endpoint", err)
	}
	connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
	if err == nil {
		closeTestTCPConnection(t, connection)
		t.Fatal("listener remained reachable after cancellation")
	}
}

func TestAcceptTCPAlreadyCanceledClosesListener(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = AcceptTCP(ctx, listener)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if !strings.Contains(err.Error(), "accept TCP connection on "+`"`+listener.Addr().String()+`"`) {
		t.Fatalf("error = %v, want named accept endpoint", err)
	}
}

func TestListenTCPAlreadyCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ListenTCP(ctx, "127.0.0.1:0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestAcceptTCPDeadlineClosesListener(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err = AcceptTCP(ctx, listener)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "accept TCP connection on "+`"`+listener.Addr().String()+`"`) {
		t.Fatalf("error = %v, want named accept endpoint", err)
	}
}

func TestListenTCPBindFailureNamesEndpoint(t *testing.T) {
	t.Parallel()

	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close occupied listener: %v", err)
		}
	})
	address := occupied.Addr().String()
	_, err = ListenTCP(t.Context(), address)
	if err == nil || !strings.Contains(err.Error(), "listen on TCP endpoint "+`"`+address+`"`) {
		t.Fatalf("error = %v, want named TCP endpoint", err)
	}
}

func closeTestTCPConnection(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close TCP connection: %v", err)
	}
}
