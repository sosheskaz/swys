//go:build unix

package main

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const runAsNPCEnvironment = "NPC_TEST_RUN_AS_NPC"

// TestMain lets the tests below re-execute the test binary as the npc
// command, so real signals exercise the real main.
func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(runAsNPCEnvironment); ok {
		os.Args = append([]string{"npc"}, strings.Fields(arguments)...)
		main()
		return
	}
	os.Exit(m.Run())
}

func TestSignalsEndTheProcessWithTheShellStatus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		message string
		signal  syscall.Signal
		status  int
	}{
		{name: "interrupt", signal: syscall.SIGINT, message: "npc: interrupted", status: 130},
		{name: "terminate", signal: syscall.SIGTERM, message: "npc: terminated", status: 143},
		{name: "hangup", signal: syscall.SIGHUP, message: "npc: terminated", status: 129},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			process := exec.CommandContext(t.Context(), os.Args[0])
			process.Env = append(os.Environ(), runAsNPCEnvironment+"=net listen 127.0.0.1:0 --verbose")
			stderr, err := process.StderrPipe()
			require.NoError(t, err)
			require.NoError(t, process.Start())
			watchdog := time.AfterFunc(20*time.Second, func() { _ = process.Process.Kill() }) //nolint:errcheck // the process may already have exited
			defer watchdog.Stop()

			// The listening diagnostic proves main installed its handler and
			// is now waiting for a peer.
			reader := bufio.NewReader(stderr)
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(line, "listening tcp "), "first stderr line: %q", line)
			require.NoError(t, process.Process.Signal(test.signal))
			remaining, err := io.ReadAll(reader)
			require.NoError(t, err)
			waitErr := process.Wait()

			var exitErr *exec.ExitError
			require.ErrorAs(t, waitErr, &exitErr)
			require.Equal(t, test.status, exitErr.ExitCode())
			assert.Equal(t, test.message, strings.TrimSpace(string(remaining)), "stderr after signal")
		})
	}
}
