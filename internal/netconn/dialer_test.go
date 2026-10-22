package netconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errDialAttemptBlocked     = errors.New("dial attempt blocked")
	errReboundLoopbackConnect = errors.New("connected to a rebound loopback port")
)

func TestDialerResolverOverridesTCPAddress(t *testing.T) {
	t.Parallel()
	listener := listenDialerTest(t)
	port := listenerPort(t, listener)
	resolver, err := ParseResolves([]string{"service.test:" + port + ":127.0.0.1"})
	require.NoError(t, err)

	connection, err := Dialer{Resolver: resolver}.DialTCP(t.Context(), net.JoinHostPort("service.test", port))
	require.NoError(t, err)
	assert.Equal(t, listener.Addr().String(), connection.RemoteAddr().String())
	require.NoError(t, connection.Close())
}

func TestDialerResolverTriesAddressesInOrder(t *testing.T) {
	t.Parallel()
	listener := listenDialerTest(t)
	port := listenerPort(t, listener)
	resolver, err := ParseResolves([]string{"service.test:" + port + ":192.0.2.1,127.0.0.1"})
	require.NoError(t, err)
	attempts := &dialAttempts{fail: map[string]error{net.JoinHostPort("192.0.2.1", port): refusedDialError(t)}}

	connection, err := Dialer{Resolver: resolver, control: attempts.control}.DialTCP(t.Context(), net.JoinHostPort("service.test", port))
	require.NoError(t, err)
	assert.Equal(t, listener.Addr().String(), connection.RemoteAddr().String())
	require.NoError(t, connection.Close())
	assert.Equal(t, []string{net.JoinHostPort("192.0.2.1", port), listener.Addr().String()}, attempts.addresses())
}

func TestDialerRetryRefusedRetriesOnlyWhenEveryOverrideRefuses(t *testing.T) {
	t.Parallel()
	t.Run("every address refused", func(t *testing.T) {
		t.Parallel()
		listener := listenDialerTest(t)
		port := listenerPort(t, listener)
		resolver, err := ParseResolves([]string{"service.test:" + port + ":192.0.2.1,127.0.0.1"})
		require.NoError(t, err)
		refusal := refusedDialError(t)
		// Refuse both addresses for one round, then let the loopback address connect.
		attempts := &dialAttempts{
			fail:      map[string]error{net.JoinHostPort("192.0.2.1", port): refusal},
			failFirst: map[string]error{listener.Addr().String(): refusal},
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		connection, err := Dialer{Resolver: resolver, control: attempts.control}.DialTCPRetryRefused(ctx, net.JoinHostPort("service.test", port))
		require.NoError(t, err)
		require.NoError(t, connection.Close())
		assert.Len(t, attempts.addresses(), 4, "one refused round, then a new round in order")
	})
	refusal := refusedDialError(t)
	for _, test := range []struct {
		fails map[string]error
		name  string
	}{
		{name: "another failure after a refusal stops retries", fails: map[string]error{"192.0.2.1:443": refusal, "192.0.2.2:443": errDialAttemptBlocked}},
		{name: "a refusal after another failure stops retries", fails: map[string]error{"192.0.2.1:443": errDialAttemptBlocked, "192.0.2.2:443": refusal}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver, err := ParseResolves([]string{"service.test:443:192.0.2.1,192.0.2.2"})
			require.NoError(t, err)
			attempts := &dialAttempts{fail: test.fails}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			_, err = Dialer{Resolver: resolver, control: attempts.control}.DialTCPRetryRefused(ctx, "service.test:443")
			require.ErrorIs(t, err, errDialAttemptBlocked)
			assert.True(t, isConnectionRefused(err), "the refused attempt remains in the error")
			require.NoError(t, ctx.Err(), "a mixed round must not wait for the setup deadline")
			assert.Len(t, attempts.addresses(), 2)
		})
	}
}

func TestDialerResolverOverridesUDPAddress(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })
	_, port, err := net.SplitHostPort(listener.LocalAddr().String())
	require.NoError(t, err)
	resolver, err := ParseResolves([]string{"service.test:" + port + ":127.0.0.1"})
	require.NoError(t, err)

	connection, err := Dialer{Resolver: resolver}.DialUDP(t.Context(), net.JoinHostPort("service.test", port))
	require.NoError(t, err)
	assert.Equal(t, listener.LocalAddr().String(), connection.RemoteAddr().String())
	require.NoError(t, connection.Close())
}

// dialAttempts records socket attempts and fails configured addresses: fail on
// every attempt and failFirst only on the first.
type dialAttempts struct {
	fail      map[string]error
	failFirst map[string]error
	seen      []string
	mu        sync.Mutex
}

func (attempts *dialAttempts) control(_ context.Context, _, address string, _ syscall.RawConn) error {
	attempts.mu.Lock()
	defer attempts.mu.Unlock()
	attempts.seen = append(attempts.seen, address)
	if err, exists := attempts.fail[address]; exists {
		return err
	}
	if err, exists := attempts.failFirst[address]; exists {
		delete(attempts.failFirst, address)
		return err
	}
	return nil
}

func (attempts *dialAttempts) addresses() []string {
	attempts.mu.Lock()
	defer attempts.mu.Unlock()
	return append([]string(nil), attempts.seen...)
}

// refusedDialError returns the platform's genuine refusal from a closed port.
// connectionRefusal observes one refusal from this platform's TCP stack, once per
// test binary. A parallel test can rebind a just-closed loopback port before the
// dial, so an attempt that connects or fails differently is discarded and retried.
var connectionRefusal = sync.OnceValues(func() (error, error) {
	var last error
	for range 5 {
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("reserve loopback port: %w", err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			return nil, fmt.Errorf("release loopback port: %w", err)
		}
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
		if connection != nil {
			err = errors.Join(fmt.Errorf("%w %s", errReboundLoopbackConnect, address), connection.Close())
		}
		if isConnectionRefused(err) {
			return fmt.Errorf("dial closed loopback port: %w", err), nil
		}
		last = err
	}
	return nil, fmt.Errorf("no closed loopback port refused a connection; last result: %w", last)
})

// refusedDialError returns a real connection refusal for injecting through Dialer.control.
func refusedDialError(t *testing.T) error {
	t.Helper()
	refusal, err := connectionRefusal()
	require.NoError(t, err)
	return refusal
}

// refusingDialer refuses every attempt before it connects, so retry tests need
// no closed loopback port that a parallel test could rebind. The TEST-NET-1
// address (RFC 5737) is never contacted.
func refusingDialer(t *testing.T) (Dialer, string) {
	t.Helper()
	const address = "192.0.2.1:9"
	attempts := &dialAttempts{fail: map[string]error{address: refusedDialError(t)}}
	return Dialer{control: attempts.control}, address
}

func listenDialerTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", closeErr)
		}
	})
	return listener
}

func listenerPort(t *testing.T, listener net.Listener) string {
	t.Helper()
	address, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	return strconv.Itoa(address.Port)
}
