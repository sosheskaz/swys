package netconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var (
	errDialRetryCanceled       = errors.New("dial retry canceled")
	errDialWrappedCancellation = errors.Join(errDialRetryCanceled, context.DeadlineExceeded)
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

func TestDialTCPRetryRefusedRetriesUntilContextExpires(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	connection, err := DialTCPRetryRefused(ctx, address)
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused connected to a closed loopback address")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want setup deadline after retrying connection refusal", err)
	}
}

func TestDialTCPRetryRefusedConnectsWhenListenerStarts(t *testing.T) {
	t.Parallel()

	reservation, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	type listenResult struct {
		listener net.Listener
		err      error
	}
	listenerStarted := make(chan listenResult, 1)
	timer := time.AfterFunc(2*tcpRefusedRetryInterval, func() {
		listener, listenErr := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
		listenerStarted <- listenResult{listener: listener, err: listenErr}
	})
	t.Cleanup(func() { timer.Stop() })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	connection, dialErr := DialTCPRetryRefused(ctx, address)
	result := <-listenerStarted
	if result.err != nil {
		t.Fatalf("start delayed listener: %v", result.err)
	}
	t.Cleanup(func() {
		if closeErr := result.listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close delayed listener: %v", closeErr)
		}
	})
	if dialErr != nil {
		t.Fatalf("dial before delayed listener startup: %v", dialErr)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	serverConnection, err := result.listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := serverConnection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialTCPRetryRefusedDoesNotRetryOtherErrors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	connection, err := DialTCPRetryRefused(ctx, "missing-port")
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused returned a connection for an invalid address")
	}
	if err == nil {
		t.Fatal("DialTCPRetryRefused accepted an address without a port")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("invalid address exhausted retry budget: %v", err)
	}
	select {
	case <-ctx.Done():
		t.Fatalf("invalid address waited for setup context: %v", err)
	default:
	}
}

func TestDialTCPReturnsResolverDeadlineWithUnboundedParent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestDialTCPResolverDeadlineProcess$",
		"-test.count=1",
	)
	command.Env = append(os.Environ(), "NPC_DIAL_RESOLVER_DEADLINE_PROCESS=1", "GORACE=atexit_sleep_ms=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("resolver deadline child: %v\n%s", err, output)
	}
}

func TestDialTCPResolverDeadlineProcess(_ *testing.T) { //nolint:paralleltest // isolated child mutates net.DefaultResolver and exits directly
	if os.Getenv("NPC_DIAL_RESOLVER_DEADLINE_PROCESS") != "1" {
		return
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		},
	}
	watchdog := time.AfterFunc(250*time.Millisecond, func() {
		fmt.Fprintln(os.Stderr, "DialTCP waited for an unbounded parent after the resolver deadline")
		os.Exit(2)
	})
	connection, err := DialTCP(
		context.Background(), //nolint:usetesting // an unbounded parent is the regression condition
		"resolver-deadline.invalid:80",
	)
	watchdog.Stop()
	if connection != nil {
		_ = connection.Close() //nolint:errcheck // the unexpected connection is already a test failure
		fmt.Fprintln(os.Stderr, "DialTCP returned an unexpected connection")
		os.Exit(1)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(os.Stderr, "DialTCP error = %v, want resolver deadline\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestDialTCPRetryRefusedPreservesCancellationCause(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	_, nativeRefusalErr := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if nativeRefusalErr == nil {
		t.Fatal("native TCP dial connected to a closed loopback address")
	}
	var syscallErr *os.SyscallError
	if !errors.As(nativeRefusalErr, &syscallErr) {
		t.Fatalf("native TCP refusal = %T %v, want wrapped system call error", nativeRefusalErr, nativeRefusalErr)
	}
	ctx, cancel := context.WithTimeoutCause(t.Context(), 2*tcpRefusedRetryInterval, errDialRetryCanceled)
	defer cancel()

	connection, err := DialTCPRetryRefused(ctx, address)
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused connected to a closed loopback address")
	}
	if !errors.Is(err, errDialRetryCanceled) {
		t.Fatalf("error = %v, want cancellation cause", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want canonical context deadline", err)
	}
	if !errors.Is(err, syscallErr.Err) {
		t.Fatalf("error = %v, want most recent native TCP refusal %v", err, syscallErr.Err)
	}
}

func TestDialTCPRetryRefusedPreservesWrappedCancellationCause(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeoutCause(
		t.Context(),
		2*tcpRefusedRetryInterval,
		errDialWrappedCancellation,
	)
	defer cancel()

	connection, err := DialTCPRetryRefused(ctx, address)
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused connected to a closed loopback address")
	}
	if !errors.Is(err, errDialWrappedCancellation) {
		t.Fatalf("error = %v, want exact wrapping cancellation cause", err)
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
