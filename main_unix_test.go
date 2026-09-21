//go:build unix

package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
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
			process.Env = append(os.Environ(), runAsNPCEnvironment+"=net listen tcp 127.0.0.1:0 --verbose")
			stderr, err := process.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			watchdog := time.AfterFunc(20*time.Second, func() { _ = process.Process.Kill() }) //nolint:errcheck // the process may already have exited
			defer watchdog.Stop()

			// The listening diagnostic proves main installed its handler and
			// is now waiting for a peer.
			reader := bufio.NewReader(stderr)
			if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "listening tcp ") {
				t.Fatalf("first stderr line = %q, %v, want listening diagnostic", line, err)
			}
			if err := process.Process.Signal(test.signal); err != nil {
				t.Fatal(err)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			waitErr := process.Wait()

			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != test.status {
				t.Fatalf("wait error = %v, want exit status %d", waitErr, test.status)
			}
			if got := strings.TrimSpace(string(remaining)); got != test.message {
				t.Fatalf("stderr after signal = %q, want %q", got, test.message)
			}
		})
	}
}
