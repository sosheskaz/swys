//go:build darwin || freebsd || linux

package password

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

//nolint:paralleltest // SIGCHLD observation belongs to this child process
func TestStoppedSupplierProbeDoesNotReap(t *testing.T) {
	// ^Z delivers TSTP; STOP comes from outside the terminal.
	for _, stopSignal := range []string{"TSTP", "STOP"} {
		t.Run(stopSignal, func(t *testing.T) { assertStoppedSupplierObserved(t, stopSignal) })
	}
}

func assertStoppedSupplierObserved(t *testing.T, stopSignal string) {
	t.Helper()
	notifications := make(chan os.Signal, 1)
	signal.Notify(notifications, syscall.SIGCHLD)
	defer signal.Stop(notifications)
	defaultTSTPForChildren(t)
	process := exec.CommandContext(t.Context(), "/bin/sh", "-c", "kill -"+stopSignal+" $$")
	// TSTP is discarded in an orphaned process group, which the test binary's
	// own group can be under a noninteractive runner.
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, process.Start())
	defer func() {
		_ = process.Process.Kill() //nolint:errcheck // process may already be gone
		_ = process.Wait()         //nolint:errcheck // test may have already reaped it
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for {
		stopped, err := passwordProcessStopped(process.Process.Pid)
		require.NoError(t, err)
		if stopped {
			break
		}
		select {
		case <-notifications:
		case <-ctx.Done():
			t.Fatal("child stop was not observed")
		}
	}
	require.NoError(t, process.Process.Kill())
	err := process.Wait()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
}

// defaultTSTPForChildren gives later children the default TSTP action. Shells
// without job control, such as the FreeBSD CI session, start the tests with TSTP
// ignored, and an ignored signal survives exec; a caught one is reset.
func defaultTSTPForChildren(t *testing.T) {
	t.Helper()
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, syscall.SIGTSTP)
	t.Cleanup(func() { signal.Stop(caught) })
}
