package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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
			if cause == nil || cause.Error() != test.message {
				t.Fatalf("cause = %v, want %q", cause, test.message)
			}
			if got := ExitCode(cause); got != test.code {
				t.Fatalf("exit code = %d, want %d", got, test.code)
			}
			if !errors.Is(cause, context.Canceled) || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("cause %v and error %v must both report cancellation", cause, ctx.Err())
			}
			// A second signal must already get the prior disposition once
			// the cancellation is visible.
			if got := releases.Load(); got != 1 {
				t.Fatalf("notification releases = %d, want 1 before cancellation is observable", got)
			}
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
	if got := releases.Load(); got != 1 {
		t.Fatalf("notification releases = %d, want 1", got)
	}
	if cause := context.Cause(ctx); !errors.Is(cause, context.Canceled) || ExitCode(cause) != 1 {
		t.Fatalf("cause = %v, want plain cancellation without an interrupt status", cause)
	}
}

func TestInterruptContextFollowsParentCancellation(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancelCause(t.Context())
	released := make(chan struct{})
	ctx, stop := interruptContext(parent, make(chan os.Signal), func() { close(released) }, noBackstop)
	defer stop()

	cancelParent(errTestInterruptCause)

	waitForContext(ctx, t)
	if cause := context.Cause(ctx); !errors.Is(cause, errTestInterruptCause) {
		t.Fatalf("cause = %v, want the parent's cause", cause)
	}
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("parent cancellation did not release the signal notification")
	}
}

func TestInterruptStopsHTTPRequestBlockedOnStdinBody(t *testing.T) {
	t.Parallel()
	// The server accepts through its backlog and never answers.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
	stdin := &blockingStdin{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(stdin.release) })
	run := startInterruptibleCommand(t, stdin, "http", "-X", "POST", "http://"+listener.Addr().String()+"/")
	waitForSignal(t, stdin.entered, "request never read its stdin body")

	run.signals <- os.Interrupt

	requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
}

// blockingStdin behaves like a blocking file descriptor: Close does not wake a pending Read.
type blockingStdin struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (stdin *blockingStdin) Read([]byte) (int, error) {
	stdin.once.Do(func() { close(stdin.entered) })
	<-stdin.release
	return 0, io.EOF
}

func (*blockingStdin) Close() error { return nil }

func TestExitCode(t *testing.T) {
	t.Parallel()
	interrupted := &interruptError{signal: os.Interrupt}
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
		{name: "signal without a number", err: &interruptError{signal: unnumberedSignal{}}, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitCode(test.err); got != test.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", test.err, got, test.want)
			}
		})
	}
}

func TestAttributeInterrupt(t *testing.T) {
	t.Parallel()
	interrupted, cancel := context.WithCancelCause(t.Context())
	cancel(&interruptError{signal: syscall.SIGTERM})
	live, cancelLive := context.WithCancel(t.Context())
	t.Cleanup(cancelLive)
	canceled, cancelPlain := context.WithCancel(t.Context())
	cancelPlain()

	t.Run("a run that succeeded stays successful", func(t *testing.T) {
		t.Parallel()
		if err := attributeInterrupt(interrupted, nil); err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
	})

	t.Run("a failure without a signal is untouched", func(t *testing.T) {
		t.Parallel()
		for name, err := range map[string]error{
			"live context":     attributeInterrupt(live, errTestInterruptCause),
			"canceled context": attributeInterrupt(canceled, errTestInterruptCause),
		} {
			if !errors.Is(err, errTestInterruptCause) || ExitCode(err) != 1 {
				t.Fatalf("%s: error = %v, want the original failure", name, err)
			}
		}
	})

	t.Run("any failure after a signal is the interruption", func(t *testing.T) {
		t.Parallel()
		// Teardown fallout, such as a closed connection, need not mention cancellation.
		err := attributeInterrupt(interrupted, errTestInterruptCause)
		if err == nil || err.Error() != "terminated" || ExitCode(err) != 143 {
			t.Fatalf("error = %v, exit code %d, want terminated with exit code 143", err, ExitCode(err))
		}
	})
}

func TestInterruptOf(t *testing.T) {
	t.Parallel()
	interrupted, cancel := context.WithCancelCause(t.Context())
	want := &interruptError{signal: os.Interrupt}
	cancel(want)
	plain, cancelPlain := context.WithCancelCause(t.Context())
	cancelPlain(errTestInterruptCause)

	if got := interruptOf(interrupted); got != want {
		t.Fatalf("interruptOf(interrupted) = %v, want the cancellation cause", got)
	}
	for name, ctx := range map[string]context.Context{"live": t.Context(), "canceled for another reason": plain} {
		if got := interruptOf(ctx); got != nil {
			t.Fatalf("interruptOf(%s context) = %v, want nil", name, got)
		}
	}
}

func TestInterruptContextArmsBackstopOnFirstSignal(t *testing.T) {
	t.Parallel()
	signals := make(chan os.Signal, 2)
	armed := make(chan *interruptError, 2)
	recorded := &backstop{}
	ctx, stop := interruptContext(t.Context(), signals, func() {}, func(interrupt *interruptError) *backstop {
		armed <- interrupt
		return recorded
	})

	signals <- syscall.SIGTERM
	signals <- os.Interrupt
	waitForContext(ctx, t)

	if got := <-armed; got != interruptOf(ctx) || got.signal != syscall.SIGTERM || got.backstop != recorded {
		t.Fatalf("armed for %v, want the first signal's interruption carrying the backstop", got)
	}
	if recorded.isStopped() {
		t.Fatal("backstop stopped before the run finished")
	}
	stop()
	waitUntil(t, recorded.isStopped, "finishing the run did not stop the backstop")
	if len(armed) != 0 {
		t.Fatal("a later signal armed a second backstop")
	}
}

func TestInterruptContextDoesNotArmBackstopWithoutSignal(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(t.Context())
	var armed atomic.Int32
	ctx, stop := interruptContext(parent, make(chan os.Signal), func() {}, func(*interruptError) *backstop {
		armed.Add(1)
		return &backstop{}
	})
	defer stop()

	cancelParent()
	waitForContext(ctx, t)
	stop()

	if got := armed.Load(); got != 0 {
		t.Fatalf("backstop armed %d times without a signal", got)
	}
}

func TestBackstopEndsARunThatOutlivesItsGrace(t *testing.T) {
	t.Parallel()
	exited := make(chan int, 1)
	var stderr lockedBuffer
	arm := newBackstop(10*time.Millisecond, &stderr, func(code int) { exited <- code })

	arm(&interruptError{signal: syscall.SIGTERM})

	select {
	case code := <-exited:
		if code != 143 {
			t.Fatalf("exit code = %d, want 143", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backstop never fired")
	}
	if got, want := stderr.String(), "npc: terminated (forced exit after 10ms)\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

const backstopTestGrace = 30 * time.Millisecond

func TestBackstopStaysQuietOnceStopped(t *testing.T) {
	t.Parallel()
	exited := make(chan int, 1)
	arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })

	arm(&interruptError{signal: os.Interrupt}).stop()

	select {
	case code := <-exited:
		t.Fatalf("stopped backstop exited with %d", code)
	case <-time.After(10 * backstopTestGrace):
	}
}

// A pager that owns Ctrl-C pauses the backstop; when it lets go, npc gets a
// fresh grace period rather than none.
func TestBackstopIsPausedWhileHeldAndRestartedWhenLetGo(t *testing.T) {
	t.Parallel()
	exited := make(chan int, 1)
	arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
	held := arm(&interruptError{signal: os.Interrupt})
	release := held.hold()

	select {
	case code := <-exited:
		t.Fatalf("held backstop exited with %d", code)
	case <-time.After(10 * backstopTestGrace):
	}
	released := time.Now()
	release()

	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code = %d, want 130", code)
		}
		if elapsed := time.Since(released); elapsed < backstopTestGrace {
			t.Fatalf("exited %v after being released, want a fresh grace period of %v", elapsed, backstopTestGrace)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backstop never restarted after the hold was released")
	}
}

func TestBackstopStaysPausedUntilEveryHolderLetsGo(t *testing.T) {
	t.Parallel()
	exited := make(chan int, 1)
	arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
	held := arm(&interruptError{signal: os.Interrupt})
	first, second := held.hold(), held.hold()
	first()
	first() // letting go twice must not release the second holder's claim

	select {
	case code := <-exited:
		t.Fatalf("backstop exited with %d while a holder remained", code)
	case <-time.After(10 * backstopTestGrace):
	}
	if !held.holding() {
		t.Fatal("backstop is not held although one holder remains")
	}
	second()

	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("backstop never restarted after the last hold was released")
	}
}

func TestHoldWithoutABackstopIsANoOp(t *testing.T) {
	t.Parallel()
	release := (&interruptError{signal: os.Interrupt}).hold()

	release() // must not panic
}

func TestBackstopStaysStoppedWhenHoldsAreReleasedAfterStop(t *testing.T) {
	t.Parallel()
	exited := make(chan int, 1)
	arm := newBackstop(backstopTestGrace, io.Discard, func(code int) { exited <- code })
	held := arm(&interruptError{signal: os.Interrupt})
	release := held.hold()

	held.stop()
	release()

	select {
	case code := <-exited:
		t.Fatalf("stopped backstop restarted and exited with %d", code)
	case <-time.After(10 * backstopTestGrace):
	}
}

func TestBackstopExitsEvenWhenTheNoteCannotBeWritten(t *testing.T) {
	t.Parallel()
	stalled := &stalledWriter{release: make(chan struct{})}
	t.Cleanup(func() { close(stalled.release) })
	exited := make(chan int, 1)
	arm := newBackstop(10*time.Millisecond, stalled, func(code int) { exited <- code })

	arm(&interruptError{signal: os.Interrupt})

	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code = %d, want 130", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled stderr kept the backstop from ending the run")
	}
}

// stalledWriter blocks every write until released, like a full pipe nobody reads.
type stalledWriter struct {
	release chan struct{}
}

func (w *stalledWriter) Write(data []byte) (int, error) {
	<-w.release
	return len(data), nil
}

func noBackstop(*interruptError) *backstop { return &backstop{} }

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

func waitForSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatal(failure)
	}
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
