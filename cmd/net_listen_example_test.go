package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestExampleNetListenTCPBidirectionalRelay(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader("hello from listener"),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	remainingStderr := drainExampleStderr(run.stderr)

	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "hello from client"); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("hello from listener"))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if got := string(received); got != "hello from listener" {
		t.Fatalf("client received %q, want listener input", got)
	}

	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "hello from client" {
		t.Fatalf("listener output = %q, want client payload", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted endpoint summary", stderr)
	}
}

type exampleListenRun struct {
	stderr *bufio.Reader
	stdout *bytes.Buffer
	done   <-chan error
}

func startExampleListenCommand(
	t *testing.T,
	input io.Reader,
	args ...string,
) exampleListenRun {
	t.Helper()
	resetCommandFlags(rootCmd)
	ctx, cancel := context.WithCancel(t.Context())
	setExampleCommandContext(ctx, rootCmd)
	rootCmd.SetArgs(args)
	rootCmd.SetIn(input)

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	stderrReader, stderrWriter := io.Pipe()
	rootCmd.SetErr(stderrWriter)

	done := make(chan error, 1)
	go func() {
		command, runErr := rootCmd.ExecuteC()
		runErr = errors.Join(runErr, closeCommandIO(command))
		runErr = errors.Join(runErr, stderrWriter.Close())
		done <- runErr
	}()
	t.Cleanup(func() {
		cancel()
		resetCommandFlags(rootCmd)
		setExampleCommandContext(context.WithoutCancel(t.Context()), rootCmd)
		rootCmd.SetArgs(nil)
		rootCmd.SetIn(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	return exampleListenRun{stderr: bufio.NewReader(stderrReader), stdout: &stdout, done: done}
}

func setExampleCommandContext(ctx context.Context, command *cobra.Command) {
	command.SetContext(ctx)
	for _, child := range command.Commands() {
		setExampleCommandContext(ctx, child)
	}
}

func drainExampleStderr(reader io.Reader) <-chan string {
	remaining := make(chan string, 1)
	go func() {
		data, err := io.ReadAll(reader)
		if err != nil {
			remaining <- fmt.Sprintf("read remaining stderr: %v", err)
			return
		}
		remaining <- string(data)
	}()
	return remaining
}

func readExampleListeningTCPAddress(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read listening diagnostic: %v", err)
	}
	line = strings.TrimSpace(line)
	const prefix = "listening tcp "
	address, found := strings.CutPrefix(line, prefix)
	if !found {
		t.Fatalf("listening diagnostic = %q, want prefix %q", line, prefix)
	}
	return address
}
