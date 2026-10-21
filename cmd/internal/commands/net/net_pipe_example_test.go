package net_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

func TestExampleAESRoundTripThroughNetPipe(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "aes.key")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	encrypt := newNetPipeProcess(ctx, "aes", "encrypt", "-k", keyPath)
	connect := newNetPipeProcess(ctx, "net", "connect")
	listen := newNetPipeProcess(ctx, "net", "listen", "127.0.0.1:0", "-r", "--verbose")
	decrypt := newNetPipeProcess(ctx, "aes", "decrypt", "-k", keyPath)
	commands := []*exec.Cmd{encrypt, connect, listen, decrypt}
	const connectStage, listenStage = 1, 2

	encryptedRead, encryptedWrite, err := os.Pipe()
	require.NoError(t, err)
	encrypted := [2]*os.File{encryptedRead, encryptedWrite}
	connectedRead, connectedWrite, err := os.Pipe()
	if err != nil {
		closeNetPipeFiles(t, encrypted)
		t.Fatal(err)
	}
	connected := [2]*os.File{connectedRead, connectedWrite}
	listenedRead, listenedWrite, err := os.Pipe()
	if err != nil {
		closeNetPipeFiles(t, encrypted, connected)
		t.Fatal(err)
	}
	listened := [2]*os.File{listenedRead, listenedWrite}
	pipes := []*os.File{encrypted[0], encrypted[1], connected[0], connected[1], listened[0], listened[1]}
	t.Cleanup(func() { closeNetPipeFiles(t, encrypted, connected, listened) })

	encrypt.Stdin = strings.NewReader("hello, world\n")
	encrypt.Stdout = encrypted[1]
	connect.Stdin = encrypted[0]
	connect.Stdout = connected[1]
	listen.Stdin = connected[0]
	listen.Stdout = listened[1]
	decrypt.Stdin = listened[0]
	var plaintext bytes.Buffer
	decrypt.Stdout = &plaintext
	stderrs := make([]bytes.Buffer, len(commands))
	for i, command := range commands {
		command.Stderr = &stderrs[i]
	}

	address, listenStderr := startNetPipeListener(t, commands[listenStage])
	commands[connectStage].Args = append(commands[connectStage].Args, address)
	running := []*exec.Cmd{commands[listenStage]}
	for i, command := range commands {
		if i == listenStage {
			continue
		}
		if err := command.Start(); err != nil {
			stopNetPipeProcesses(running)
			t.Fatalf("start pipeline stage %d: %v", i, err)
		}
		running = append(running, command)
	}
	for _, pipe := range pipes {
		if err := pipe.Close(); err != nil {
			stopNetPipeProcesses(commands)
			t.Fatalf("close parent pipeline descriptor: %v", err)
		}
	}

	type stageResult struct {
		err   error
		index int
	}
	results := make(chan stageResult, len(commands))
	for i, command := range commands {
		go func() { results <- stageResult{index: i, err: command.Wait()} }()
	}
	stageErrors := make([]error, len(commands))
	failed := false
	for range commands {
		result := <-results
		stageErrors[result.index] = result.err
		if result.err != nil && !failed {
			failed = true
			cancel()
		}
	}
	if err := errors.Join(stageErrors...); err != nil {
		stderrs[listenStage].WriteString(<-listenStderr)
		diagnostics := make([]string, len(commands))
		for i := range commands {
			diagnostics[i] = fmt.Sprintf("stage %d: error=%v stderr=%q", i, stageErrors[i], stderrs[i].String())
		}
		t.Fatalf("AES network pipeline failed: %v (%s)", err, strings.Join(diagnostics, "; "))
	}
	if got := plaintext.String(); got != "hello, world\n" {
		t.Fatalf("decrypted output = %q, want %q", got, "hello, world\n")
	}
}

func TestExampleDefaultDuplexTransfersFullFileToListener(t *testing.T) {
	t.Parallel()
	payload := exampleStreamPayload("default duplex request\n")
	inputPath := filepath.Join(t.TempDir(), "request.bin")
	require.NoError(t, os.WriteFile(inputPath, payload, 0o600))
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
	remainingStderr := drainExampleStderr(run.stderr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	stdout, stderr, err := executeRootCommandStreams(
		t,
		root,
		"net", "connect", address,
		"--input", inputPath,
	)
	require.NoError(t, err)
	if stdout != "" || stderr != "" {
		t.Fatalf("connector output = stdout:%q stderr:%q, want empty", stdout, stderr)
	}
	require.NoError(t, <-run.done)
	assertExamplePayload(t, run.stdout.Bytes(), payload)
	if diagnostics := <-remainingStderr; !strings.Contains(diagnostics, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted endpoint summary", diagnostics)
	}
}

func TestNetConnectTCPPeerEOFStopsBlockedInput(t *testing.T) {
	t.Parallel()
	address, serverDone := startNetPipePeerEOFServer(t, "response")
	input, inputWriter := io.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetIn(input)

	stdout, stderr, err := executeRootCommandStreams(
		t,
		root,
		"net", "connect", address,
		"--duplex=false",
	)
	require.NoError(t, inputWriter.Close())
	require.NoError(t, err, "default TCP command waited for input after peer EOF: %v", err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	require.NoError(t, <-serverDone)
}

func TestNetPipeCommandProcess(_ *testing.T) { //nolint:paralleltest // the subprocess exits directly after executing one command
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
	root := newRootCmd()
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
	processArguments := []string{"-test.run=^TestNetPipeCommandProcess$", "-test.count=1", "--"}
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
	require.NoError(t, err)
	t.Cleanup(func() { closeNetPipeFiles(t, [2]*os.File{stderrRead, stderrWrite}) })
	listen.Stderr = stderrWrite
	require.NoError(t, listen.Start())
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
	return address, drainExampleStderr(stderr)
}

func startNetPipePeerEOFServer(t *testing.T, response string) (string, <-chan error) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close peer EOF listener: %v", err)
		}
	})
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		_, writeErr := io.WriteString(connection, response)
		done <- errors.Join(writeErr, connection.Close())
	}()
	return listener.Addr().String(), done
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
