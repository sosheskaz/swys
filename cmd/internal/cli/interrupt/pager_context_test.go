package interrupt

import (
	"context"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGuidePagerIsTerminatedByPlainCancellation(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(t.Context())
	ctx, release := PagerContext(parent)
	defer release()

	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("context was not canceled")
	}
}

func TestGuidePagerContextReleaseCancelsPager(t *testing.T) {
	t.Parallel()
	ctx, release := PagerContext(t.Context())
	release()

	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("context was not canceled")
	}
}

func TestPagerContextLetsGoOfTheBackstopOnRelease(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		signals := make(chan os.Signal, 1)
		recorded := &backstop{}
		ctx, stop := interruptContext(t.Context(), signals, func() {}, func(*Error) *backstop { return recorded })
		defer stop()
		_, release := PagerContext(ctx)
		signals <- os.Interrupt
		synctest.Wait()
		assert.True(t, recorded.holding(), "pager did not pause the backstop")

		release()
		release() // ending the pager after a termination signal already released it
		synctest.Wait()
		assert.False(t, recorded.holding(), "backstop is still paused after the pager ended")
	})
}

func TestPagerContextDoesNotPauseTheBackstopAfterItEnded(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		signals := make(chan os.Signal, 1)
		recorded := &backstop{}
		ctx, stop := interruptContext(t.Context(), signals, func() {}, func(*Error) *backstop { return recorded })
		defer stop()
		_, release := PagerContext(ctx)
		release()

		signals <- os.Interrupt
		synctest.Wait()
		assert.False(t, recorded.holding(), "an ended pager paused the backstop")
	})
}
