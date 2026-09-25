// Package interrupt exposes controlled signals to its external contract tests.
package interrupt

import (
	"context"
	"io"
	"os"
	"os/signal"
	"time"
)

type BackstopProbe struct{ backstop *backstop }

// NewControlledContext lets external package tests exercise pager behavior
// against the real interrupt context with a supplied signal channel.
func NewControlledContext(parent context.Context, signals <-chan os.Signal) (context.Context, context.CancelFunc, *BackstopProbe) {
	recorded := &backstop{}
	ctx, stop := interruptContext(parent, signals, func() {}, func(*Error) *backstop { return recorded })
	return ctx, stop, &BackstopProbe{backstop: recorded}
}

func (probe *BackstopProbe) Holding() bool {
	return probe.backstop.holding()
}

func NewDelayedSignalContext(parent context.Context, pause func(), beforeStop bool) (context.Context, context.CancelFunc) {
	if beforeStop {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, interruptSignals()...)
		return interruptContext(parent, signals, func() {
			signal.Stop(signals)
			pause()
		}, func(*Error) *backstop { return &backstop{} })
	}
	return withInterrupt(parent, func(*Error) *backstop {
		pause()
		return &backstop{}
	})
}

func NewBackstopSignalContext(parent context.Context, grace time.Duration, stderr io.Writer, exit func(int)) (context.Context, context.CancelFunc) {
	return withInterrupt(parent, newBackstop(grace, stderr, exit))
}
