package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ExampleExitCode() {
	fmt.Println(ExitCode(nil))
	fmt.Println(ExitCode(errTestCommandFailed))
	fmt.Println(ExitCode(&interruptError{signal: os.Interrupt}))
	fmt.Println(ExitCode(&interruptError{signal: syscall.SIGTERM}))
	// Output:
	// 0
	// 1
	// 130
	// 143
}

func TestInterruptExamples(t *testing.T) {
	t.Parallel()

	t.Run("Ctrl-C stops a listener waiting for a peer", func(t *testing.T) {
		t.Parallel()
		run := startInterruptibleCommand(t, strings.NewReader(""), "net", "listen", "127.0.0.1:0", "--verbose")
		readExampleListeningAddress(t, run.stderr, "listening tcp ")
		drainExampleStderr(run.stderr)

		run.signals <- os.Interrupt

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
	})

	t.Run("SIGTERM stops an established relay", func(t *testing.T) {
		t.Parallel()
		stdin, stdinWriter := io.Pipe()
		t.Cleanup(func() { _ = stdinWriter.Close() }) //nolint:errcheck // test cleanup is best effort
		run := startInterruptibleCommand(t, stdin, "net", "listen", "127.0.0.1:0", "--verbose")
		address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
		drainExampleStderr(run.stderr)
		connection := dialListenTestTCP(t, address)
		t.Cleanup(func() { closeListenTestTCP(t, connection) })

		run.signals <- syscall.SIGTERM

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "terminated", 143)
	})

	t.Run("Ctrl-C stops a hash waiting on stdin", func(t *testing.T) {
		t.Parallel()
		stdin, stdinWriter := io.Pipe()
		t.Cleanup(func() { _ = stdinWriter.Close() }) //nolint:errcheck // test cleanup is best effort
		run := startInterruptibleCommand(t, stdin, "hash", "sha256")

		run.signals <- os.Interrupt

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
	})

	t.Run("a failure without a signal keeps exit status 1", func(t *testing.T) {
		t.Parallel()
		run := startInterruptibleCommand(t, strings.NewReader(""), "hash", "sha256", "--input", "/nonexistent/npc-input")

		err := waitForInterruptedRun(t, run.done)

		if err == nil || ExitCode(err) != 1 {
			t.Fatalf("error = %v, exit code %d, want failure with exit code 1", err, ExitCode(err))
		}
	})
}

type interruptibleRun struct {
	signals chan<- os.Signal
	stderr  *bufio.Reader
	done    <-chan error
}

// startInterruptibleCommand runs the root command under the same context
// wiring as ExecuteContext, with an injected signal source.
func startInterruptibleCommand(t *testing.T, input io.Reader, args ...string) interruptibleRun {
	t.Helper()
	signals := make(chan os.Signal, 1)
	ctx, stop := interruptContext(t.Context(), signals, func() {}, noBackstop)
	t.Cleanup(stop)

	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(input)
	root.SetOut(io.Discard)
	stderrReader, stderrWriter := io.Pipe()
	root.SetErr(stderrWriter)

	done := make(chan error, 1)
	go func() {
		err := executeContext(ctx, root)
		done <- errors.Join(err, stderrWriter.Close())
	}()
	return interruptibleRun{signals: signals, stderr: bufio.NewReader(stderrReader), done: done}
}

func waitForInterruptedRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("command did not stop")
		return nil
	}
}

func requireInterrupted(t *testing.T, err error, message string, code int) {
	t.Helper()
	if err == nil || err.Error() != message {
		t.Fatalf("error = %v, want %q", err, message)
	}
	if got := ExitCode(err); got != code {
		t.Fatalf("exit code = %d, want %d", got, code)
	}
}
