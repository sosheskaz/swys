//go:build unix

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

const (
	pagerSignalHelperEnvironment = "NPC_TEST_PAGER_SIGNAL_HELPER"
	pagerSignalRaceEnvironment   = "NPC_TEST_PAGER_SIGNAL_RACE"
)

// Hold the root signal handler before it records the first signal or its
// cancellation cause. The pager can stop and reap the child in that interval.
func TestPagerTerminationRetainsSignalStatusWhenRootHandlerRunsLater(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name            string
		firstSignal     syscall.Signal
		laterSignal     syscall.Signal
		pauseBeforeStop bool
		status          int
	}{
		{name: "SIGTERM alone", firstSignal: syscall.SIGTERM, status: 143},
		{name: "SIGINT then SIGTERM during arm", firstSignal: syscall.SIGINT, laterSignal: syscall.SIGTERM, status: 130},
		{name: "SIGINT then SIGTERM during notify stop", firstSignal: syscall.SIGINT, laterSignal: syscall.SIGTERM, pauseBeforeStop: true, status: 130},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testPagerTerminationWithDelayedRootHandler(t, test.firstSignal, test.laterSignal, test.pauseBeforeStop, test.status)
		})
	}
}

func testPagerTerminationWithDelayedRootHandler(t *testing.T, firstSignal, laterSignal syscall.Signal, pauseBeforeStop bool, wantStatus int) {
	t.Helper()
	directory := t.TempDir()
	if pauseBeforeStop {
		if err := os.WriteFile(filepath.Join(directory, "pause-before-stop"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPagerSignalRaceHelperProcess$")
	helper.Env = append(os.Environ(), pagerSignalRaceEnvironment+"="+directory)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	pagerPID := 0
	finished := false
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(directory, "release-root"), nil, 0o600) //nolint:errcheck // cleanup also kills the helper
		if pagerPID != 0 {
			_ = syscall.Kill(pagerPID, syscall.SIGKILL) //nolint:errcheck // pager may already be gone
		}
		if !finished {
			_ = helper.Process.Kill() //nolint:errcheck // helper may already be gone
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("helper did not exit after cleanup")
			}
		}
	})
	pagerPID = waitForPagerPID(t, filepath.Join(directory, "started"))
	if err := helper.Process.Signal(firstSignal); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(directory, "result")
	rootReceivedPath := filepath.Join(directory, "root-received")
	if laterSignal != 0 {
		waitForFile(t, rootReceivedPath)
		select {
		case err := <-done:
			finished = true
			t.Fatalf("run ended after first signal: %v", err)
		default:
		}
		if err := syscall.Kill(pagerPID, 0); err != nil {
			t.Fatalf("pager ended after first signal: %v", err)
		}
		if err := helper.Process.Signal(laterSignal); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, func() bool {
		_, rootErr := os.Stat(rootReceivedPath)
		_, resultErr := os.Stat(resultPath)
		return rootErr == nil || resultErr == nil
	}, "neither root handler nor pager result observed the termination signal")
	if _, err := os.Stat(rootReceivedPath); err == nil {
		waitUntil(t, func() bool { return errors.Is(syscall.Kill(pagerPID, 0), syscall.ESRCH) }, "pager was not reaped while root signal handling was paused")
	}

	// A result published before the root handler resumes must already carry the
	// signal status. Otherwise let the handler finish, then inspect the result.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(resultPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(directory, "release-root"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, resultPath)
	result, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != strconv.Itoa(wantStatus) {
		t.Fatalf("termination result = %q, want signal exit status %d", result, wantStatus)
	}
	select {
	case err := <-done:
		finished = true
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantStatus {
			t.Fatalf("helper ended with %v, want exit status %d", err, wantStatus)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper outlived the termination signal")
	}
}

func TestPagerSignalRaceHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	directory, ok := os.LookupEnv(pagerSignalRaceEnvironment)
	if !ok {
		t.Parallel()
		return
	}
	pauseRoot := func() {
		if err := os.WriteFile(filepath.Join(directory, "root-received"), nil, 0o600); err != nil {
			os.Exit(91)
		}
		for {
			if _, err := os.Stat(filepath.Join(directory, "release-root")); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	var ctx context.Context
	var stop context.CancelFunc
	if _, err := os.Stat(filepath.Join(directory, "pause-before-stop")); err == nil {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, interruptSignals()...)
		ctx, stop = interruptContext(t.Context(), signals, func() {
			signal.Stop(signals)
			pauseRoot()
		}, func(_ *interruptError) *backstop { return &backstop{} })
	} else {
		ctx, stop = withInterrupt(t.Context(), func(_ *interruptError) *backstop {
			pauseRoot()
			return &backstop{}
		})
	}
	command := &cobra.Command{}
	command.SetContext(ctx)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	pager := guidePagerHelperCommand("hold", filepath.Join(directory, "started"), filepath.Join(directory, "release-pager"))
	err := attributeInterrupt(ctx, presentGuideThroughPager(command, defaultGuideDependencies(), pager, []byte("guide\n")))
	status := ExitCode(err)
	resultTemporary := filepath.Join(directory, "result-temporary")
	if err := os.WriteFile(resultTemporary, []byte(strconv.Itoa(status)), 0o600); err != nil {
		os.Exit(92)
	}
	if err := os.Rename(resultTemporary, filepath.Join(directory, "result")); err != nil {
		os.Exit(92)
	}
	stop()
	os.Exit(status)
}

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
