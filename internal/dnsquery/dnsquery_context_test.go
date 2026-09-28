package dnsquery

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	externalDNS "codeberg.org/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlaintextCancellationCannotBeOverwrittenByReadDeadline(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { assert.NoError(t, client.Close()) }()
		defer func() { assert.NoError(t, server.Close()) }()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		conn := &cancelBeforeReadDeadlineConn{Conn: client, cancel: cancel}
		go func() {
			_, err := io.Copy(io.Discard, server) // Drain the query without answering.
			assert.NoError(t, err)
		}()

		started := time.Now()
		_, err := exchangePlaintextConn(ctx, &externalDNS.Msg{}, conn, time.Hour)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, time.Since(started), "cancellation must finish without waiting for the replacement read deadline")
	})
}

type cancelBeforeReadDeadlineConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (conn *cancelBeforeReadDeadlineConn) SetReadDeadline(deadline time.Time) error {
	// Force cancellation after the DNS client checks ctx.Err(), but before it
	// installs its read deadline: the ordering from the CI hang.
	conn.cancel()
	synctest.Wait()
	return conn.Conn.SetReadDeadline(deadline) //nolint:wrapcheck // Preserve the wrapped connection behavior.
}

func TestWatchDNSConnectionContextCancellationWinsDeadlineSetup(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx := &cancelDuringDeadlineContext{
			done:     make(chan struct{}),
			deadline: time.Now().Add(time.Hour),
		}
		conn := &deadlineRecordingConn{}

		stop, err := watchDNSConnectionContext(ctx, conn)
		require.NoError(t, err)
		defer stop()
		synctest.Wait()

		deadline, ok := conn.lastDeadline()
		require.True(t, ok, "connection deadline was not set")
		assert.False(t, deadline.After(time.Now()), "cancellation deadline %s must be no later than now", deadline)
		assert.ErrorIs(t, ctx.Err(), context.Canceled)
	})
}

func TestContextErrorAddsElapsedDeadline(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Model a socket deadline firing before context cancellation publishes ctx.Err().
		ctx := elapsedDeadlineContext{deadline: time.Now().Add(time.Hour)}
		timeoutErr := &net.DNSError{Err: "fixture timeout", IsTimeout: true}
		time.Sleep(time.Hour)

		err := contextError(ctx, timeoutErr)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, timeoutErr)
	})
}

type elapsedDeadlineContext struct {
	deadline time.Time
}

func (ctx elapsedDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func (elapsedDeadlineContext) Done() <-chan struct{} {
	return nil
}

func (elapsedDeadlineContext) Err() error {
	return nil
}

func (elapsedDeadlineContext) Value(any) any {
	return nil
}

type cancelDuringDeadlineContext struct {
	done     chan struct{}
	deadline time.Time
	once     sync.Once
}

func (ctx *cancelDuringDeadlineContext) Deadline() (time.Time, bool) {
	ctx.once.Do(func() { close(ctx.done) })
	synctest.Wait()
	return ctx.deadline, true
}

func (ctx *cancelDuringDeadlineContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *cancelDuringDeadlineContext) Err() error {
	select {
	case <-ctx.done:
		return context.Canceled
	default:
		return nil
	}
}

func (*cancelDuringDeadlineContext) Value(any) any {
	return nil
}

type deadlineRecordingConn struct {
	deadlines []time.Time
	mu        sync.Mutex
}

func (*deadlineRecordingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (*deadlineRecordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (*deadlineRecordingConn) Close() error {
	return nil
}

func (*deadlineRecordingConn) LocalAddr() net.Addr {
	return deadlineRecordingAddr("local")
}

func (*deadlineRecordingConn) RemoteAddr() net.Addr {
	return deadlineRecordingAddr("remote")
}

func (conn *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.deadlines = append(conn.deadlines, deadline)
	return nil
}

func (*deadlineRecordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*deadlineRecordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (conn *deadlineRecordingConn) lastDeadline() (time.Time, bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.deadlines) == 0 {
		return time.Time{}, false
	}
	return conn.deadlines[len(conn.deadlines)-1], true
}

type deadlineRecordingAddr string

func (deadlineRecordingAddr) Network() string {
	return "test"
}

func (address deadlineRecordingAddr) String() string {
	return string(address)
}
