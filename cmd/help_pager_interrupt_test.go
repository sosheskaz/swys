package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestGuidePagerSurvivesInterruptCancellation(t *testing.T) {
	t.Parallel()
	run := startHeldPager(t)

	run.signals <- os.Interrupt
	waitForContext(run.ctx, t)

	// The pager owns Ctrl-C, so the backstop must not end the run beneath it.
	waitUntil(t, run.backstop.holding, "pager did not pause the backstop while it owns Ctrl-C")
	// Killing the pager would fire as soon as the context is canceled, so the
	// wait below must see it still running.
	select {
	case err := <-run.done:
		t.Fatalf("interrupt ended the pager: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	run.releasePager(t)
	if err := <-run.done; err != nil {
		t.Fatalf("pager after interrupt: %v", err)
	}
	waitUntil(t, func() bool { return !run.backstop.holding() }, "pager did not let go of the backstop when it ended")
}

func TestGuidePagerIsTerminatedByOtherSignals(t *testing.T) {
	t.Parallel()
	for _, signal := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(signal.String(), func(t *testing.T) {
			t.Parallel()
			run := startHeldPager(t)

			run.signals <- signal

			select {
			case err := <-run.done:
				if err == nil {
					t.Fatal("pager exited cleanly, want it terminated with the command")
				}
				if run.backstop.holding() {
					t.Fatal("pager paused the backstop for a signal that is not Ctrl-C")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("pager outlived the terminating signal")
			}
		})
	}
}

func TestGuidePagerIsTerminatedByPlainCancellation(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(t.Context())
	ctx, release := pagerProcessContext(parent)
	defer release()

	cancel()

	waitForContext(ctx, t)
}

func TestGuidePagerContextReleaseCancelsPager(t *testing.T) {
	t.Parallel()
	ctx, release := pagerProcessContext(t.Context())

	release()

	waitForContext(ctx, t)
}

func TestPagerContextLetsGoOfTheBackstopOnRelease(t *testing.T) {
	t.Parallel()
	signals := make(chan os.Signal, 1)
	recorded := &backstop{}
	ctx, stop := interruptContext(t.Context(), signals, func() {}, func(*interruptError) *backstop { return recorded })
	t.Cleanup(stop)
	_, release := pagerProcessContext(ctx)
	signals <- os.Interrupt
	waitUntil(t, recorded.holding, "pager did not pause the backstop")

	release()
	release() // ending the pager after a termination signal already released it

	if recorded.holding() {
		t.Fatal("backstop is still paused after the pager ended")
	}
}

func TestPagerContextDoesNotPauseTheBackstopAfterItEnded(t *testing.T) {
	t.Parallel()
	signals := make(chan os.Signal, 1)
	recorded := &backstop{}
	ctx, stop := interruptContext(t.Context(), signals, func() {}, func(*interruptError) *backstop { return recorded })
	t.Cleanup(stop)
	_, release := pagerProcessContext(ctx)
	release()

	signals <- os.Interrupt
	waitForContext(ctx, t)

	time.Sleep(50 * time.Millisecond)
	if recorded.holding() {
		t.Fatal("an ended pager paused the backstop")
	}
}

type heldPagerRun struct {
	ctx      context.Context //nolint:containedctx // the test observes the command's context
	backstop *backstop
	signals  chan<- os.Signal
	done     <-chan error
	release  string
}

// startHeldPager presents a guide through a pager that stays alive until
// releasePager is called or the pager is killed.
func startHeldPager(t *testing.T) heldPagerRun {
	t.Helper()
	signals := make(chan os.Signal, 1)
	recorded := &backstop{}
	ctx, stop := interruptContext(t.Context(), signals, func() {}, func(*interruptError) *backstop { return recorded })
	t.Cleanup(stop)
	directory := t.TempDir()
	started := filepath.Join(directory, "started")
	release := filepath.Join(directory, "release")

	command := &cobra.Command{}
	command.SetContext(ctx)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() {
		done <- presentGuideThroughPager(command, defaultGuideDependencies(), guidePagerHelperCommand("hold", started, release), []byte("guide\n"))
	}()
	t.Cleanup(func() {
		// Let a still-running helper exit so the test leaves no process behind.
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Error(err)
		}
	})
	waitForFile(t, started)
	return heldPagerRun{ctx: ctx, backstop: recorded, signals: signals, done: done, release: release}
}

func (run heldPagerRun) releasePager(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(run.release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s was not created", path)
}
