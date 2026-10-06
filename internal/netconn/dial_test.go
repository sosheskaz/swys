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
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errDialRetryCanceled       = errors.New("dial retry canceled")
	errDialWrappedCancellation = errors.Join(errDialRetryCanceled, context.DeadlineExceeded)
)

func TestDialTCPConnectsToLoopback(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
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
	require.NoError(t, err)
	require.NoError(t, connection.Close())

	select {
	case serverConnection := <-accepted:
		require.NoError(t, serverConnection.Close())
	case <-time.After(time.Second):
		t.Fatal("TCP connection was not accepted")
	}
}

func TestDialTCPRetryRefusedRetriesUntilContextExpires(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	connection, err := DialTCPRetryRefused(ctx, address)
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused connected to a closed loopback address")
	}
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDialTCPRetryRefusedConnectsWhenListenerStarts(t *testing.T) {
	t.Parallel()

	reservation, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := reservation.Addr().String()
	require.NoError(t, reservation.Close())
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
	require.NoError(t, connection.Close())
	serverConnection, err := result.listener.Accept()
	require.NoError(t, err)
	require.NoError(t, serverConnection.Close())
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
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithTimeoutCause(t.Context(), 2*tcpRefusedRetryInterval, errDialRetryCanceled)
	defer cancel()

	connection, err := DialTCPRetryRefused(ctx, address)
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close unexpected connection: %v", closeErr)
		}
		t.Fatal("DialTCPRetryRefused connected to a closed loopback address")
	}
	require.ErrorIs(t, err, errDialRetryCanceled)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, isConnectionRefused(err), "retry error must preserve connection-refused identity: %v", err)
}

func TestDialTCPRetryRefusedPreservesWrappedCancellationCause(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
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
	require.ErrorIs(t, err, errDialWrappedCancellation)
}

func TestWithContextCausePreservesPendingSocketDeadlineCause(t *testing.T) {
	t.Parallel()

	socketErr := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	require.NotErrorIs(t, socketErr, context.DeadlineExceeded)
	for _, test := range []struct {
		err      error
		name     string
		deadline bool
		future   bool
		wantWait bool
	}{
		{name: "reached socket deadline", err: socketErr, deadline: true, wantWait: true},
		{name: "unrelated error at deadline", err: io.ErrUnexpectedEOF, deadline: true},
		{name: "socket timeout before deadline", err: socketErr, deadline: true, future: true},
		{name: "socket timeout without deadline", err: socketErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				ctx := pendingDialDeadlineContext{Context: parent}
				if test.deadline {
					ctx.deadline = time.Now()
					if test.future {
						ctx.deadline = ctx.deadline.Add(time.Second)
					}
				}
				require.NoError(t, ctx.Err())
				result := make(chan error, 1)
				go func() {
					result <- withContextCause(ctx, test.err)
				}()
				synctest.Wait()
				var got error
				returned := false
				select {
				case got = <-result:
					returned = true
				default:
				}
				assert.Equal(t, !test.wantWait, returned, "return before context cause publication")
				cancel(errDialWrappedCancellation)
				synctest.Wait()
				if !returned {
					select {
					case got = <-result:
					default:
						t.Fatal("error helper did not return after context cause publication")
					}
				}
				require.ErrorIs(t, got, test.err, "preserve original dial failure")
				if test.wantWait {
					require.ErrorIs(t, got, errDialWrappedCancellation)
					require.ErrorIs(t, got, context.DeadlineExceeded)
				} else {
					require.NotErrorIs(t, got, errDialWrappedCancellation)
				}
			})
		})
	}
}

// The socket deadline is visible before cancellation publishes its cause.
// Publication is explicitly released by the test rather than a scheduled timer.
type pendingDialDeadlineContext struct {
	context.Context //nolint:containedctx // retain standard cause values while gating deadline publication
	deadline        time.Time
}

func (ctx pendingDialDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, !ctx.deadline.IsZero()
}

func (ctx pendingDialDeadlineContext) Err() error {
	if ctx.Context.Err() != nil {
		return context.DeadlineExceeded
	}
	return nil
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
	require.NoError(t, err)
	require.NotEmpty(t, connection.ConnectionState().VerifiedChains, "verified TLS chains")
	require.NoError(t, connection.Close())

	select {
	case got := <-serverName:
		assert.Equal(t, "example.com", got, "SNI")
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
	require.NoError(t, err)
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
	require.ErrorIs(t, err, context.Canceled)
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
	require.ErrorIs(t, err, context.Canceled)
	if connection != nil {
		t.Fatal("DialTLS returned a connection for a canceled context")
	}
	if !strings.Contains(err.Error(), "dial TCP endpoint") {
		t.Fatalf("error = %v, want TCP setup context", err)
	}
}
