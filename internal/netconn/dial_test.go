package netconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDialTCPConnectsToLoopback(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", closeErr)
		}
	})
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	connection, err := DialTCP(t.Context(), listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case serverConnection := <-accepted:
		if err := serverConnection.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP connection was not accepted")
	}
}

func TestDialTLSVerifiesPeerAndPreservesSNI(t *testing.T) {
	t.Parallel()

	serverName := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName <- hello.ServerName
			return nil, nil //nolint:nilnil // nil directs TLS to continue with the existing configuration
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	connection, err := DialTLS(t.Context(), server.Listener.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(connection.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("verified TLS connection has no verified chains")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-serverName:
		if got != "example.com" {
			t.Fatalf("SNI = %q, want example.com", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive ClientHello")
	}
}

func TestDialTLSRejectsUntrustedPeer(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)

	connection, err := DialTLS(t.Context(), server.Listener.Addr().String(), &tls.Config{ServerName: "example.com"})
	if err == nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("DialTLS accepted an untrusted peer")
	}
	if connection != nil {
		t.Fatal("DialTLS returned a connection after verification failure")
	}
}

func TestDialTLSCancellationClosesConnection(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close stalled TLS listener: %v", closeErr)
		}
	})
	serverAccepted := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		close(serverAccepted)
		_, copyErr := io.Copy(io.Discard, connection)
		serverDone <- errors.Join(copyErr, connection.Close())
	}()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type dialResult struct {
		connection *tls.Conn
		err        error
	}
	dialDone := make(chan dialResult, 1)
	go func() {
		connection, err := DialTLS(ctx, listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
		})
		dialDone <- dialResult{connection: connection, err: err}
	}()
	select {
	case <-serverAccepted:
		cancel()
	case result := <-dialDone:
		t.Fatalf("DialTLS returned before cancellation: connection = %v, error = %v", result.connection, result.err)
	case <-time.After(time.Second):
		t.Fatal("server did not accept the TLS connection")
	}
	result := <-dialDone
	connection, err := result.connection, result.err
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if connection != nil {
		t.Fatal("DialTLS returned a connection after cancellation")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server connection cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled TLS handshake did not close the TCP connection")
	}
}

func TestDialTLSRejectsCanceledContextBeforeDial(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	connection, err := DialTLS(ctx, "127.0.0.1:1", &tls.Config{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if connection != nil {
		t.Fatal("DialTLS returned a connection for a canceled context")
	}
	if !strings.Contains(err.Error(), "dial TCP endpoint") {
		t.Fatalf("error = %v, want TCP setup context", err)
	}
}
