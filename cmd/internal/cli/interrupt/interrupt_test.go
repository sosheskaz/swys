package interrupt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestInterruptCause = errors.New("test cancellation cause")

type unnumberedSignal struct{}

func (unnumberedSignal) Signal() {}

func (unnumberedSignal) String() string { return "unnumbered" }

func TestInterruptContextCancelsWithSignalCause(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		signal  os.Signal
		name    string
		message string
		code    int
	}{
		{name: "interrupt", signal: os.Interrupt, message: "interrupted", code: 130},
		{name: "terminate", signal: syscall.SIGTERM, message: "terminated", code: 143},
		{name: "hangup", signal: syscall.SIGHUP, message: "terminated", code: 129},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			signals := make(chan os.Signal, 1)
			var releases atomic.Int32
			ctx, stop := interruptContext(t.Context(), signals, func() { releases.Add(1) }, noBackstop)
			defer stop()

			signals <- test.signal
			waitForContext(ctx, t)

			cause := context.Cause(ctx)
			require.EqualError(t, cause, test.message)
			require.Equal(t, test.code, ExitCode(cause))
			require.ErrorIs(t, cause, context.Canceled)
			require.ErrorIs(t, ctx.Err(), context.Canceled)
			// A second signal must already get the prior disposition once
			// the cancellation is visible.
			assert.Equal(t, int32(1), releases.Load(), "notification released before cancellation is observable")
		})
	}
}

func TestInterruptContextStopReleasesNotificationOnce(t *testing.T) {
	t.Parallel()
	var releases atomic.Int32
	ctx, stop := interruptContext(t.Context(), make(chan os.Signal), func() { releases.Add(1) }, noBackstop)

	stop()
	stop()

	waitForContext(ctx, t)
	require.Equal(t, int32(1), releases.Load(), "notification releases")
	cause := context.Cause(ctx)
	require.ErrorIs(t, cause, context.Canceled)
	assert.Equal(t, 1, ExitCode(cause), "plain cancellation without an interrupt status")
}

func TestInterruptContextFollowsParentCancellation(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancelCause(t.Context())
	released := make(chan struct{})
	ctx, stop := interruptContext(parent, make(chan os.Signal), func() { close(released) }, noBackstop)
	defer stop()

	cancelParent(errTestInterruptCause)

	waitForContext(ctx, t)
	require.ErrorIs(t, context.Cause(ctx), errTestInterruptCause)
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("parent cancellation did not release the signal notification")
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()
	interrupted := &Error{signal: os.Interrupt}
	for _, test := range []struct {
		err  error
		name string
		want int
	}{
		{name: "success", err: nil, want: 0},
		{name: "failure", err: errTestInterruptCause, want: 1},
		{name: "interrupt", err: interrupted, want: 130},
		{name: "wrapped interrupt", err: fmt.Errorf("execute command: %w", interrupted), want: 130},
		{name: "joined interrupt", err: errors.Join(errTestInterruptCause, interrupted), want: 130},
		{name: "signal without a number", err: &Error{signal: unnumberedSignal{}}, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.want, ExitCode(test.err), "ExitCode(%v)", test.err)
		})
	}
}

func TestAttributeInterrupt(t *testing.T) {
	t.Parallel()
	interrupted, cancel := context.WithCancelCause(t.Context())
	cancel(&Error{signal: syscall.SIGTERM})
	live, cancelLive := context.WithCancel(t.Context())
	t.Cleanup(cancelLive)
	canceled, cancelPlain := context.WithCancel(t.Context())
	cancelPlain()

	t.Run("a run that succeeded stays successful", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, attributeInterrupt(interrupted, nil))
	})

	t.Run("a failure without a signal is untouched", func(t *testing.T) {
		t.Parallel()
		for name, err := range map[string]error{
			"live context":     attributeInterrupt(live, errTestInterruptCause),
			"canceled context": attributeInterrupt(canceled, errTestInterruptCause),
		} {
			require.ErrorIs(t, err, errTestInterruptCause, name)
			require.Equal(t, 1, ExitCode(err), name)
		}
	})

	t.Run("any failure after a signal is the interruption", func(t *testing.T) {
		t.Parallel()
		// Teardown fallout, such as a closed connection, need not mention cancellation.
		err := attributeInterrupt(interrupted, errTestInterruptCause)
		require.EqualError(t, err, "terminated")
		assert.Equal(t, 143, ExitCode(err))
	})
}

func TestInterruptOf(t *testing.T) {
	t.Parallel()
	interrupted, cancel := context.WithCancelCause(t.Context())
	want := &Error{signal: os.Interrupt}
	cancel(want)
	plain, cancelPlain := context.WithCancelCause(t.Context())
	cancelPlain(errTestInterruptCause)

	require.Same(t, want, interruptOf(interrupted))
	for name, ctx := range map[string]context.Context{"live": t.Context(), "canceled for another reason": plain} {
		assert.Nil(t, interruptOf(ctx), "%s context", name)
	}
}

func TestInterruptContextArmsBackstopOnFirstSignal(t *testing.T) {
	t.Parallel()
	signals := make(chan os.Signal, 2)
	armed := make(chan *Error, 2)
	recorded := &backstop{}
	ctx, stop := interruptContext(t.Context(), signals, func() {}, func(interrupt *Error) *backstop {
		armed <- interrupt
		return recorded
	})

	signals <- syscall.SIGTERM
	signals <- os.Interrupt
	waitForContext(ctx, t)

	if got := <-armed; got != interruptOf(ctx) || got.signal != syscall.SIGTERM || got.backstop != recorded {
		t.Fatalf("armed for %v, want the first signal's interruption carrying the backstop", got)
	}
	require.False(t, recorded.isStopped(), "backstop stopped before the run finished")
	stop()
	waitUntil(t, recorded.isStopped, "finishing the run did not stop the backstop")
	assert.Empty(t, armed, "a later signal armed a second backstop")
}

func TestInterruptContextDoesNotArmBackstopWithoutSignal(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(t.Context())
	var armed atomic.Int32
	ctx, stop := interruptContext(parent, make(chan os.Signal), func() {}, func(*Error) *backstop {
		armed.Add(1)
		return &backstop{}
	})
	defer stop()

	cancelParent()
	waitForContext(ctx, t)
	stop()

	assert.Zero(t, armed.Load(), "backstop armed without a signal")
}

func TestBackstopEndsARunThatOutlivesItsGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const grace = 10 * time.Millisecond
		exited := make(chan int, 1)
		var stderr lockedBuffer
		arm := newBackstop(grace, &stderr, func(code int) { exited <- code })

		arm(&Error{signal: syscall.SIGTERM})
		synctest.Sleep(grace - time.Nanosecond)
		select {
		case code := <-exited:
			t.Fatalf("backstop exited early with %d", code)
		default:
		}
		synctest.Sleep(time.Nanosecond)
		select {
		case code := <-exited:
			require.Equal(t, 143, code)
		default:
			t.Fatal("backstop did not exit after its grace period")
		}
		assert.Equal(t, "npc: terminated (forced exit after 10ms)\n", stderr.String())
	})
}

const backstopTestGrace = 30 * time.Millisecond

func TestBackstopStaysQuietOnceStopped(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		exited := make(chan int, 1)
		arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })

		arm(&Error{signal: os.Interrupt}).stop()
		synctest.Sleep(10 * backstopTestGrace)

		select {
		case code := <-exited:
			t.Fatalf("stopped backstop exited with %d", code)
		default:
		}
	})
}

// A pager that owns Ctrl-C pauses the backstop; when it lets go, npc gets a
// fresh grace period rather than none.
func TestBackstopIsPausedWhileHeldAndRestartedWhenLetGo(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		exited := make(chan int, 1)
		arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
		held := arm(&Error{signal: os.Interrupt})
		release := held.hold()

		synctest.Sleep(10 * backstopTestGrace)
		select {
		case code := <-exited:
			t.Fatalf("held backstop exited with %d", code)
		default:
		}
		release()

		synctest.Sleep(backstopTestGrace - time.Nanosecond)
		select {
		case code := <-exited:
			t.Fatalf("backstop exited early with %d", code)
		default:
		}
		synctest.Sleep(time.Nanosecond)
		select {
		case code := <-exited:
			require.Equal(t, 130, code)
		default:
			t.Fatal("backstop did not exit after its grace period")
		}
	})
}

func TestBackstopStaysPausedUntilEveryHolderLetsGo(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		exited := make(chan int, 1)
		arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
		held := arm(&Error{signal: os.Interrupt})
		first, second := held.hold(), held.hold()
		first()
		first() // letting go twice must not release the second holder's claim

		synctest.Sleep(10 * backstopTestGrace)
		select {
		case code := <-exited:
			t.Fatalf("backstop exited with %d while a holder remained", code)
		default:
		}
		if !held.holding() {
			t.Fatal("backstop is not held although one holder remains")
		}
		second()

		synctest.Sleep(backstopTestGrace - time.Nanosecond)
		select {
		case code := <-exited:
			t.Fatalf("backstop exited early with %d", code)
		default:
		}
		synctest.Sleep(time.Nanosecond)
		select {
		case code := <-exited:
			require.Equal(t, 130, code)
		default:
			t.Fatal("backstop did not exit after its grace period")
		}
	})
}

func TestHoldWithoutABackstopIsANoOp(t *testing.T) {
	t.Parallel()
	release := (&Error{signal: os.Interrupt}).hold()

	release() // must not panic
}

func TestBackstopStaysStoppedWhenHoldsAreReleasedAfterStop(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		exited := make(chan int, 1)
		arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
		held := arm(&Error{signal: os.Interrupt})
		release := held.hold()

		held.stop()
		release()
		synctest.Sleep(10 * backstopTestGrace)

		select {
		case code := <-exited:
			t.Fatalf("stopped backstop restarted and exited with %d", code)
		default:
		}
	})
}

func TestBackstopExitsEvenWhenTheNoteCannotBeWritten(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const grace = 10 * time.Millisecond
		stalled := &stalledWriter{release: make(chan struct{})}
		defer close(stalled.release)
		exited := make(chan int, 1)
		arm := newBackstop(grace, stalled, func(code int) { exited <- code })

		arm(&Error{signal: os.Interrupt})
		synctest.Sleep(grace + forcedExitNoteWait - time.Nanosecond)
		select {
		case code := <-exited:
			t.Fatalf("backstop exited early with %d", code)
		default:
		}
		synctest.Sleep(time.Nanosecond)
		select {
		case code := <-exited:
			require.Equal(t, 130, code)
		default:
			t.Fatal("backstop did not exit after waiting for stalled stderr")
		}
	})
}

// stalledWriter blocks every write until released, like a full pipe nobody reads.
type stalledWriter struct {
	release chan struct{}
}

func (w *stalledWriter) Write(data []byte) (int, error) {
	<-w.release
	return len(data), nil
}

func noBackstop(*Error) *backstop { return &backstop{} }

func (b *backstop) holding() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.holds > 0
}

func (b *backstop) isStopped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped
}

// lockedBuffer collects output written from the backstop's timer goroutine.
type lockedBuffer struct {
	buffer strings.Builder
	mu     sync.Mutex
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data) //nolint:wrapcheck // strings.Builder never fails
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func waitUntil(t *testing.T, condition func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(failure)
}

func waitForContext(ctx context.Context, t *testing.T) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("context was not canceled")
	}
}
