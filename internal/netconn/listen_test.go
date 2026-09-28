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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAndAcceptTCPPortZero(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	listener, err := ListenTCP(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := AcceptTCP(ctx, listener)
		accepted <- connection
		acceptErr <- err
	}()

	client, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	require.NoError(t, err)
	t.Cleanup(func() { closeTestTCPConnection(t, client) })
	server := <-accepted
	require.NoError(t, <-acceptErr)
	if server == nil {
		t.Fatal("accepted connection is nil")
	}
	t.Cleanup(func() { closeTestTCPConnection(t, server) })
	assert.Equal(t, address, server.LocalAddr().String(), "accepted local address")

	second, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
	if err == nil {
		closeTestTCPConnection(t, second)
		t.Fatal("listener accepted a second connection")
	}
}

func TestListenAndAcceptTCPWildcardHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host    string
		name    string
		network string
	}{
		{name: "IPv4", network: "tcp4", host: "127.0.0.1"},
		{name: "IPv6", network: "tcp6", host: "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.network == "tcp6" {
				probe, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				require.NoError(t, probe.Close())
			}

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			listener, err := ListenTCP(ctx, ":0")
			require.NoError(t, err)
			tcpAddress, ok := listener.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("listener address type = %T, want *net.TCPAddr", listener.Addr())
			}
			port := tcpAddress.Port
			accepted := make(chan error, 1)
			go func() {
				connection, err := AcceptTCP(ctx, listener)
				if connection != nil {
					err = errors.Join(err, connection.Close())
				}
				accepted <- err
			}()

			connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(
				t.Context(),
				test.network,
				net.JoinHostPort(test.host, strconv.Itoa(port)),
			)
			require.NoError(t, err)
			closeTestTCPConnection(t, connection)
			require.NoError(t, <-accepted)
		})
	}
}

func TestAcceptTCPCancellationClosesListener(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	accepted := make(chan error, 1)
	go func() {
		_, err := AcceptTCP(ctx, listener)
		accepted <- err
	}()
	cancel()
	err = <-accepted
	require.ErrorIs(t, err, context.Canceled)
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
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = AcceptTCP(ctx, listener)
	require.ErrorIs(t, err, context.Canceled)
	if !strings.Contains(err.Error(), "accept TCP connection on "+`"`+listener.Addr().String()+`"`) {
		t.Fatalf("error = %v, want named accept endpoint", err)
	}
}

func TestListenTCPAlreadyCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ListenTCP(ctx, "127.0.0.1:0")
	require.ErrorIs(t, err, context.Canceled)
}

func TestAcceptTCPDeadlineClosesListener(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err = AcceptTCP(ctx, listener)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	if !strings.Contains(err.Error(), "accept TCP connection on "+`"`+listener.Addr().String()+`"`) {
		t.Fatalf("error = %v, want named accept endpoint", err)
	}
}

func TestListenTCPBindFailureNamesEndpoint(t *testing.T) {
	t.Parallel()

	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
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

func TestAcceptTLSCompletesVerifiedServerHandshake(t *testing.T) {
	t.Parallel()

	serverConfig, clientConfig := newAcceptTLSTestConfigs(t)
	serverConfig.NextProtos = []string{"npc-test"}
	clientConfig.NextProtos = []string{"npc-test"}
	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	serverName := make(chan string, 1)
	negotiated := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := AcceptTLS(t.Context(), listener, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		state := connection.ConnectionState()
		serverName <- state.ServerName
		negotiated <- state.NegotiatedProtocol
		request := make([]byte, len("request"))
		_, readErr := io.ReadFull(connection, request)
		_, writeErr := io.WriteString(connection, "response")
		serverDone <- errors.Join(readErr, writeErr, connection.Close())
	}()

	client, err := DialTLS(t.Context(), listener.Addr().String(), clientConfig)
	require.NoError(t, err)
	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("response"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	closeTestTCPConnection(t, client)
	require.Equal(t, "response", string(response))
	require.Equal(t, "example.com", <-serverName, "SNI")
	require.Equal(t, "npc-test", <-negotiated, "ALPN")
	require.NoError(t, <-serverDone)
}

func TestAcceptTLSHandshakeDeadlineClosesConnection(t *testing.T) {
	t.Parallel()

	serverConfig, _ := newAcceptTLSTestConfigs(t)
	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		_, err := AcceptTLS(ctx, listener, serverConfig)
		serverDone <- err
	}()
	client, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	require.NoError(t, err)
	require.ErrorIs(t, <-serverDone, context.DeadlineExceeded)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 1)
	if n, err := client.Read(buffer); n != 0 || err == nil {
		t.Fatalf("client read = (%d, %v), want closed connection", n, err)
	}
	closeTestTCPConnection(t, client)
	second, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
	if err == nil {
		closeTestTCPConnection(t, second)
		t.Fatal("TLS listener remained reachable after failed handshake")
	}
}

func TestAcceptTLSHandshakeCancellationClosesConnection(t *testing.T) {
	t.Parallel()

	serverConfig, _ := newAcceptTLSTestConfigs(t)
	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	serverDone := make(chan error, 1)
	go func() {
		_, err := AcceptTLS(ctx, listener, serverConfig)
		serverDone <- err
	}()
	client, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	cancel()
	require.ErrorIs(t, <-serverDone, context.Canceled)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 1)
	if n, err := client.Read(buffer); n != 0 || err == nil {
		t.Fatalf("client read = (%d, %v), want closed connection", n, err)
	}
	closeTestTCPConnection(t, client)
}

func TestAcceptTLSRejectsCanceledContextBeforeAccept(t *testing.T) {
	t.Parallel()

	listener, err := ListenTCP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	connection, err := AcceptTLS(ctx, listener, &tls.Config{})
	require.ErrorIs(t, err, context.Canceled)
	if connection != nil {
		t.Fatal("AcceptTLS returned a connection for a canceled context")
	}
	client, dialErr := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
	if dialErr == nil {
		closeTestTCPConnection(t, client)
		t.Fatal("TLS listener remained reachable after canceled accept")
	}
}

func TestCloseTCPConnectionReportsInvalidConnection(t *testing.T) {
	t.Parallel()

	err := closeTCPConnection(&net.TCPConn{})
	if err == nil || !strings.Contains(err.Error(), "close accepted TCP connection") {
		t.Fatalf("error = %v, want accepted TCP close context", err)
	}
}

func TestCloseTCPConnectionClosesEstablishedConnection(t *testing.T) {
	t.Parallel()

	connection, peer := newTCPStreamPair(t)
	require.NoError(t, closeTCPConnection(connection))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 1)
	if read, err := peer.Read(buffer); read != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer read = (%d, %v), want closed connection EOF", read, err)
	}
}

func newAcceptTLSTestConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	source := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := source.Certificate()
	serverIdentity := source.TLS.Certificates[0]
	source.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{Certificates: []tls.Certificate{serverIdentity}}, &tls.Config{
		RootCAs:    roots,
		ServerName: "example.com",
	}
}

func closeTestTCPConnection(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close TCP connection: %v", err)
	}
}
