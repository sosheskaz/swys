package interrupt_test

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/interrupt"
)

func TestGuidePagerSurvivesInterruptCancellation(t *testing.T) {
	t.Parallel()
	run := startHeldPager(t)

	run.signals <- os.Interrupt
	waitForContext(run.ctx, t)

	// The pager owns Ctrl-C, so the backstop must not end the run beneath it.
	waitUntil(t, run.backstop.Holding, "pager did not pause the backstop while it owns Ctrl-C")
	// Killing the pager would fire as soon as the context is canceled, so the
	// wait below must see it still running.
	select {
	case err := <-run.done:
		t.Fatalf("interrupt ended the pager: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	run.releasePager(t)
	require.NoError(t, <-run.done, "pager after interrupt")
	waitUntil(t, func() bool { return !run.backstop.Holding() }, "pager did not let go of the backstop when it ended")
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
				require.Error(t, err, "pager exited cleanly, want it terminated with the command")
				require.False(t, run.backstop.Holding(), "pager paused the backstop for a signal that is not Ctrl-C")
			case <-time.After(10 * time.Second):
				t.Fatal("pager outlived the terminating signal")
			}
		})
	}
}

type heldPagerRun struct {
	ctx      context.Context //nolint:containedctx // the test observes the command's context
	backstop *interrupt.BackstopProbe
	signals  chan<- os.Signal
	done     <-chan error
	release  string
}

func startHeldPager(t *testing.T) heldPagerRun {
	t.Helper()
	signals := make(chan os.Signal, 1)
	ctx, stop, backstop := interrupt.NewControlledContext(t.Context(), signals)
	t.Cleanup(stop)
	directory := t.TempDir()
	started := filepath.Join(directory, "started")
	release := filepath.Join(directory, "release")

	root := &cobra.Command{Use: "npc"}
	root.AddCommand(&cobra.Command{Use: "net", Run: func(*cobra.Command, []string) {}})
	root.SetContext(ctx)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"help", "net"})
	require.NoError(t, help.RegisterGuides(root, fstest.MapFS{"guides/net.md": &fstest.MapFile{Data: []byte("# Net\n")}}))
	help.Configure(root, help.Dependencies{
		Getenv: func(key string) (string, bool) {
			if key == "PAGER" {
				return "hold", true
			}
			return "", false
		},
		Terminal: func(io.Writer) (bool, int) { return true, 80 },
		Command: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInterruptPagerHelperProcess$", "--", started, release)
		},
	}, nil)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- root.Execute()
	}()
	t.Cleanup(func() {
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Error(err)
		}
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("pager command did not finish during cleanup")
		}
	})
	select {
	case err := <-done:
		t.Fatalf("guide command exited before pager started: %v", err)
	default:
	}
	waitForFile(t, started)
	return heldPagerRun{ctx: ctx, backstop: backstop, signals: signals, done: done, release: release}
}

func (run heldPagerRun) releasePager(t *testing.T) {
	t.Helper()
	require.NoError(t, os.WriteFile(run.release, nil, 0o600))
}

func TestInterruptPagerHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	marker := -1
	for index, argument := range os.Args {
		if argument == "--" {
			marker = index
			break
		}
	}
	if marker < 0 {
		t.Parallel()
		return
	}
	if len(os.Args) != marker+3 {
		os.Exit(91)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(92)
	}
	if err := os.WriteFile(os.Args[marker+1], nil, 0o600); err != nil {
		os.Exit(93)
	}
	for {
		if _, err := os.Stat(os.Args[marker+2]); err == nil {
			os.Exit(0)
		}
		time.Sleep(10 * time.Millisecond)
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
