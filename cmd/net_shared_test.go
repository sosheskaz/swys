package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
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

func unusedNetPipeAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		closeErr := listener.Close()
		t.Fatalf("parse reserved pipeline address: %v (close listener: %v)", err, closeErr)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("localhost", port)
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
