package dnsquery

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestWatchDNSConnectionContextCancellationWinsDeadlineSetup(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx := &cancelDuringDeadlineContext{
			done:     make(chan struct{}),
			deadline: time.Now().Add(time.Hour),
		}
		conn := &deadlineRecordingConn{}

		stop, err := watchDNSConnectionContext(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		synctest.Wait()

		deadline, ok := conn.lastDeadline()
		if !ok {
			t.Fatal("connection deadline was not set")
		}
		if deadline.After(time.Now()) {
			t.Fatalf("connection deadline = %s, want cancellation deadline no later than now", deadline)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
		}
	})
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
