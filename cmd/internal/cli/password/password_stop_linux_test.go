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
	notifications := make(chan os.Signal, 1)
	signal.Notify(notifications, syscall.SIGCHLD)
	defer signal.Stop(notifications)
	process := exec.CommandContext(t.Context(), "/bin/sh", "-c", "kill -STOP $$")
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
