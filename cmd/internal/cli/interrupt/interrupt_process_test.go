//go:build unix

package interrupt

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

const backstopHelperEnvironment = "SWYS_TEST_BACKSTOP_HELPER"

// The backstop exists for stalls, and a stalled stderr is one: its note must
// not be able to keep the process alive. Only a real pipe shows that boundary.
func TestBackstopExitsWhenStderrIsStalled(t *testing.T) {
	t.Parallel()
	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBackstopHelperProcess$")
	helper.Env = append(os.Environ(), backstopHelperEnvironment+"=1")
	helper.Stderr = stallPipe(t)
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("helper announced %q, %v, want ready", line, err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	time.Sleep(300 * time.Millisecond)

	if err := helper.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 143 {
			t.Fatalf("helper ended with %v, want exit status 143", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled stderr kept the backstop from ending the process")
	}
}

func TestBackstopHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	if _, ok := os.LookupEnv(backstopHelperEnvironment); !ok {
		t.Parallel()

		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	ctx, stop := interruptContext(t.Context(), signals, func() { signal.Stop(signals) }, newBackstop(100*time.Millisecond, os.Stderr, os.Exit))
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		stop()
		os.Exit(2)
	}
	<-ctx.Done()
	// A run that never finishes: only the backstop can end it.
	time.Sleep(time.Minute)
	stop()
}

// stallPipe returns the write end of a pipe that is full and never read, for a
// child to inherit as stderr so that its next write blocks. Callers give the
// filler a moment to run before relying on the pipe being full.
func stallPipe(t *testing.T) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close() //nolint:errcheck // test cleanup is best effort
		_ = writer.Close() //nolint:errcheck // test cleanup is best effort
	})
	go func() {
		chunk := make([]byte, 4096)
		for {
			if _, err := writer.Write(chunk); err != nil {
				return
			}
		}
	}()
	return writer
}
