package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

func TestAESNetPipeCommandProcess(_ *testing.T) { //nolint:paralleltest // the subprocess exits directly after executing one command
	if os.Getenv("SWYS_NET_PIPE_COMMAND_PROCESS") != "1" {
		return
	}
	separator := -1
	for i, argument := range os.Args {
		if argument == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator == len(os.Args)-1 {
		fmt.Fprintln(os.Stderr, "missing net pipe child command")
		os.Exit(2)
	}
	root := NewCommand()
	root.SetIn(os.Stdin)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SetArgs(os.Args[separator+1:])
	if err := commandio.Execute(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func newNetPipeProcess(ctx context.Context, arguments ...string) *exec.Cmd {
	processArguments := []string{"-test.run=^TestAESNetPipeCommandProcess$", "-test.count=1", "--"}
	processArguments = append(processArguments, arguments...)
	command := exec.CommandContext(ctx, os.Args[0], processArguments...)
	raceOptions := strings.TrimSpace(os.Getenv("GORACE") + " atexit_sleep_ms=0")
	command.Env = append(os.Environ(), "SWYS_NET_PIPE_COMMAND_PROCESS=1", "GORACE="+raceOptions)
	return command
}

// startNetPipeListener starts a verbose port-0 net listen stage, replacing its
// stderr, and returns the address from its listening diagnostic with a channel
// for its remaining stderr. The child binds before announcing the port, so no
// other test can claim it first, unlike a port reserved and released by the parent.
func startNetPipeListener(t *testing.T, listen *exec.Cmd) (string, <-chan string) {
	t.Helper()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeNetPipeFiles(t, [2]*os.File{stderrRead, stderrWrite}) })
	listen.Stderr = stderrWrite
	if err := listen.Start(); err != nil {
		t.Fatal(err)
	}
	if err := stderrWrite.Close(); err != nil {
		stopNetPipeProcesses([]*exec.Cmd{listen})
		t.Fatalf("close parent listener stderr: %v", err)
	}
	stderr := bufio.NewReader(stderrRead)
	line, err := stderr.ReadString('\n')
	address, found := strings.CutPrefix(strings.TrimSpace(line), "listening tcp ")
	if err != nil || !found {
		stopNetPipeProcesses([]*exec.Cmd{listen})
		rest, readErr := io.ReadAll(stderr)
		t.Fatalf("listener stderr = %q (%v), want listening address", line+string(rest), errors.Join(err, readErr))
	}
	remaining := make(chan string, 1)
	go func() {
		data, err := io.ReadAll(stderr)
		if err != nil {
			remaining <- fmt.Sprintf("read remaining stderr: %v", err)
			return
		}
		remaining <- string(data)
	}()
	return address, remaining
}

func closeNetPipeFiles(t *testing.T, pipes ...[2]*os.File) {
	t.Helper()
	for _, pipe := range pipes {
		for _, file := range pipe {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Errorf("close pipeline descriptor: %v", err)
			}
		}
	}
}

func stopNetPipeProcesses(commands []*exec.Cmd) {
	for _, command := range commands {
		if command.Process != nil {
			_ = command.Process.Kill() //nolint:errcheck // best-effort cleanup after a pipeline setup failure
		}
	}
	for _, command := range commands {
		if command.Process != nil {
			_ = command.Wait() //nolint:errcheck // the setup failure is authoritative
		}
	}
}
