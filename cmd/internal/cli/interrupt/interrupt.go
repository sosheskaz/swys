// Package interrupt attributes command cancellation to process signals.
package interrupt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	// interruptGrace is how long a run may outlive its first signal before the
	// backstop ends it.
	interruptGrace = 5 * time.Second
	// forcedExitNoteWait bounds the backstop's stderr note so a stalled stderr
	// cannot keep the run alive.
	forcedExitNoteWait = 100 * time.Millisecond
)

// Error is the context cause when a terminating signal cancels a run.
type Error struct {
	signal os.Signal
	// backstop is set before the interruption is published; nil when none is armed.
	backstop *backstop
}

type interruptSignalKey struct{}

type firstInterrupt struct {
	ready  chan struct{}
	signal os.Signal
}

// Error is the text printed after "swys:" when a signal ends a run.
func (interrupt *Error) Error() string {
	if interrupt.signal == os.Interrupt {
		return "interrupted"
	}
	return "terminated"
}

// Is reports an interruption as context.Canceled.
func (*Error) Is(target error) bool {
	return target == context.Canceled
}

// exitCode is 128 plus the signal number, as shells report it.
func (interrupt *Error) exitCode() int {
	if number, ok := interrupt.signal.(syscall.Signal); ok {
		return 128 + int(number)
	}
	return 1
}

// hold pauses the backstop while a foreground child owns the signal. The
// returned func lets go, which starts a fresh grace period.
func (interrupt *Error) hold() func() {
	if interrupt.backstop == nil {
		return func() {}
	}
	return interrupt.backstop.hold()
}

// ExitCode maps the error from Execute or ExecuteContext to an exit status.
// A run cut short by a signal exits with 128 plus the signal number.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var interrupt *Error
	if errors.As(err, &interrupt) {
		return interrupt.exitCode()
	}
	return 1
}

// WithInterrupt returns a context canceled by the first terminating signal; a
// second signal gets the signal's prior behavior. A run still going interruptGrace
// after the first signal is ended anyway. SIGPIPE is left alone so "swys | head"
// still ends on a closed stdout.
func WithInterrupt(parent context.Context) (context.Context, context.CancelFunc) {
	return withInterrupt(parent, newBackstop(interruptGrace, os.Stderr, os.Exit))
}

// withInterrupt is WithInterrupt with the backstop injected for tests.
func withInterrupt(parent context.Context, arm func(*Error) *backstop) (context.Context, context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, interruptSignals()...)
	return interruptContext(parent, signals, func() { signal.Stop(signals) }, arm)
}

// interruptContext is withInterrupt with the signal source injected for tests.
// The returned cancel func also disarms the backstop.
func interruptContext(
	parent context.Context,
	signals <-chan os.Signal,
	stopNotify func(),
	arm func(*Error) *backstop,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	firstSignal := &firstInterrupt{ready: make(chan struct{})}
	ctx = context.WithValue(ctx, interruptSignalKey{}, firstSignal)
	release := sync.OnceFunc(stopNotify)
	finished := make(chan struct{})
	finish := sync.OnceFunc(func() { close(finished) })
	go func() {
		select {
		case received := <-signals:
			firstSignal.signal = received
			close(firstSignal.ready)
			// Release first so a second signal already gets the prior behavior.
			release()
			interrupt := &Error{signal: received}
			interrupt.backstop = arm(interrupt)
			defer interrupt.backstop.stop()
			cancel(interrupt)
			<-finished
		case <-ctx.Done():
			close(firstSignal.ready)
			release()
		}
	}()
	return ctx, func() {
		cancel(nil)
		release()
		finish()
	}
}

// firstInterruptSignal waits for the root handler's signal decision, which is
// available before it releases notification or arms the backstop.
func firstInterruptSignal(ctx context.Context) os.Signal {
	if first, ok := ctx.Value(interruptSignalKey{}).(*firstInterrupt); ok {
		<-first.ready
		return first.signal
	}
	return nil
}

// backstop ends a run that is still going a grace period after its first
// signal, for stalls no context can reach, such as a write to a stalled stdout.
// A foreground child that owns the signal can pause it and later let go.
type backstop struct {
	timer   *time.Timer // nil for a backstop that never fires
	mu      sync.Mutex
	grace   time.Duration
	holds   int
	stopped bool
}

// newBackstop arms a backstop per interruption. Its stderr note is best effort
// and never delays the exit.
func newBackstop(grace time.Duration, stderr io.Writer, exit func(int)) func(*Error) *backstop {
	return func(interrupt *Error) *backstop {
		return &backstop{
			grace: grace,
			timer: time.AfterFunc(grace, func() {
				noted := make(chan struct{})
				go func() {
					defer close(noted)
					_, _ = fmt.Fprintf(stderr, "swys: %v (forced exit after %s)\n", interrupt, grace) //nolint:errcheck // the process is exiting
				}()
				select {
				case <-noted:
				case <-time.After(forcedExitNoteWait):
				}
				exit(interrupt.exitCode())
			}),
		}
	}
}

func (b *backstop) hold() func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.holds++
	if b.timer != nil {
		b.timer.Stop()
	}
	return sync.OnceFunc(b.release)
}

func (b *backstop) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.holds--
	if b.holds == 0 && !b.stopped && b.timer != nil {
		b.timer.Reset(b.grace)
	}
}

func (b *backstop) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	if b.timer != nil {
		b.timer.Stop()
	}
}

// interruptOf returns the interruption that canceled ctx, or nil.
func interruptOf(ctx context.Context) *Error {
	var interrupt *Error
	if errors.As(context.Cause(ctx), &interrupt) {
		return interrupt
	}
	return nil
}

// attributeInterrupt reports a failure after a signal as the interruption.
func attributeInterrupt(ctx context.Context, err error) error {
	if interrupt := interruptOf(ctx); interrupt != nil && err != nil {
		return interrupt
	}
	return err
}

// NewError records a terminating signal for a command result.
func NewError(received os.Signal) *Error { return &Error{signal: received} }

// Signal returns the terminating signal.
func (interrupt *Error) Signal() os.Signal { return interrupt.signal }

// Hold pauses the forced-exit backstop while a child handles the signal.
func (interrupt *Error) Hold() func() { return interrupt.hold() }

// Of returns the signal cause of a canceled context, if any.
func Of(ctx context.Context) *Error { return interruptOf(ctx) }

// FirstSignal waits for the root signal decision.
func FirstSignal(ctx context.Context) os.Signal { return firstInterruptSignal(ctx) }

// Attribute reports an error after a signal as that interruption.
func Attribute(ctx context.Context, err error) error { return attributeInterrupt(ctx, err) }

// PagerContext keeps Ctrl-C from killing the pager: the terminal sends
// SIGINT to the pager too, and exec.CommandContext would kill it while swys
// waits to reap it. Any other cancellation still terminates the pager.
//
// While the pager owns Ctrl-C the backstop is paused; releasing the returned
// func, when the pager ends or a termination signal ends it, starts a fresh grace period.
func PagerContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	var (
		mu       sync.Mutex
		letGo    func()
		finished bool
	)
	stop := context.AfterFunc(parent, func() {
		interrupt := interruptOf(parent)
		if interrupt == nil || interrupt.Signal() != os.Interrupt {
			cancel()
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			letGo = interrupt.Hold()
		}
	})
	return ctx, func() {
		stop()
		cancel()
		mu.Lock()
		defer mu.Unlock()
		finished = true
		if letGo != nil {
			letGo()
			letGo = nil
		}
	}
}
