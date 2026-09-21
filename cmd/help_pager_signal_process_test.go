//go:build unix

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

const pagerSignalHelperEnvironment = "NPC_TEST_PAGER_SIGNAL_HELPER"

// The root handler stops intercepting after its first signal, so only real
// signals delivered to a real process show what a later one does to the pager.
func TestPagerEndsWithNPCAfterTerminationSignals(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		signals       []syscall.Signal
		status        int
		stalledStderr bool
	}{
		{name: "Ctrl-C then SIGTERM", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}, status: 130},
		{name: "Ctrl-C then SIGHUP", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGHUP}, status: 130},
		{name: "SIGTERM alone", signals: []syscall.Signal{syscall.SIGTERM}, status: 143},
		{name: "SIGHUP alone", signals: []syscall.Signal{syscall.SIGHUP}, status: 129},
		// The diagnostic blocks on a full stderr, so only the backstop can end the run.
		{name: "Ctrl-C then SIGTERM with a stalled stderr", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}, status: 130, stalledStderr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPagerSignalHelperProcess$")
			helper.Env = append(os.Environ(), pagerSignalHelperEnvironment+"="+directory)
			if test.stalledStderr {
				helper.Stderr = stallPipe(t)
			}
			if err := helper.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- helper.Wait() }()
			pagerPID := waitForPagerPID(t, filepath.Join(directory, "started"))
			t.Cleanup(func() { _ = syscall.Kill(pagerPID, syscall.SIGKILL) }) //nolint:errcheck // the pager is normally already gone
			if test.stalledStderr {
				// Let the filler stall the pipe before the first signal.
				time.Sleep(300 * time.Millisecond)
			}

			for i, signal := range test.signals {
				if err := helper.Process.Signal(signal); err != nil {
					t.Fatal(err)
				}
				if i == len(test.signals)-1 {
					break
				}
				// Ctrl-C belongs to the pager, so both processes must keep running.
				select {
				case err := <-done:
					t.Fatalf("%v ended the run: %v", signal, err)
				case <-time.After(300 * time.Millisecond):
				}
				if syscall.Kill(pagerPID, 0) != nil {
					t.Fatalf("%v ended the pager", signal)
				}
			}

			select {
			case err := <-done:
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != test.status {
					t.Fatalf("helper ended with %v, want exit status %d", err, test.status)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("run outlived the termination signal")
			}
			waitUntil(t, func() bool { return errors.Is(syscall.Kill(pagerPID, 0), syscall.ESRCH) }, "pager outlived npc")
		})
	}
}

func TestPagerSignalHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	directory, ok := os.LookupEnv(pagerSignalHelperEnvironment)
	if !ok {
		t.Parallel()

		return
	}
	ctx, stop := withInterrupt(t.Context(), newBackstop(100*time.Millisecond, os.Stderr, os.Exit))
	command := &cobra.Command{}
	command.SetContext(ctx)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	pager := guidePagerHelperCommand("hold", filepath.Join(directory, "started"), filepath.Join(directory, "release"))
	err := attributeInterrupt(ctx, presentGuideThroughPager(command, defaultGuideDependencies(), pager, []byte("guide\n")))
	if err != nil {
		// Like main, report on stderr, which the stalled-stderr case has filled.
		_, _ = fmt.Fprintf(os.Stderr, "npc: %v\n", err)
	}
	status := ExitCode(err)
	stop()
	os.Exit(status)
}

func waitForPagerPID(t *testing.T, path string) int {
	t.Helper()
	var pid int
	waitUntil(t, func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(string(data))
		return err == nil
	}, "pager never recorded its process ID")
	return pid
}

func TestTerminateOnReceiveEndsThePagerOnASignal(t *testing.T) {
	t.Parallel()
	received := make(chan os.Signal, 1)
	terminated := make(chan struct{})
	stop := terminateOnReceive(received, func() { close(terminated) })
	defer stop()

	received <- syscall.SIGTERM

	waitForSignal(t, terminated, "the pager was not terminated")
}

func TestTerminateOnReceiveStaysQuietOnceStopped(t *testing.T) {
	t.Parallel()
	received := make(chan os.Signal, 1)
	terminated := make(chan struct{})
	stop := terminateOnReceive(received, func() { close(terminated) })

	stop()
	received <- syscall.SIGTERM

	select {
	case <-terminated:
		t.Fatal("a stopped subscription still terminated the pager")
	case <-time.After(50 * time.Millisecond):
	}
}
