//go:build unix

package grpc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd"
	grpccommand "github.com/sosheskaz/swys/cmd/internal/commands/grpc"
)

const (
	grpcSignalHelperMarker             = "swys-grpc-signal-helper"
	grpcSignalBareExecuteEnvironment   = "SWYS_GRPC_SIGNAL_BARE_EXECUTE"
	grpcSignalBlockedStderrEnvironment = "SWYS_GRPC_SIGNAL_BLOCK_STDERR"
	grpcSignalRootContextSuffix        = ".context-canceled"
	grpcSignalCanceledExitCode         = 42
	grpcSignalInputSize                = 1 << 20
)

type grpcSignalCase struct {
	name    string
	message string
	signal  syscall.Signal
	status  int
}

var grpcSignalCases = []grpcSignalCase{
	{name: "interrupt", signal: syscall.SIGINT, message: "interrupted", status: 130},
	{name: "terminate", signal: syscall.SIGTERM, message: "terminated", status: 143},
	{name: "hangup", signal: syscall.SIGHUP, message: "terminated", status: 129},
}

func TestGRPCExecuteSignalsCancelBlockingInput(t *testing.T) {
	t.Parallel()

	for _, signalCase := range grpcSignalCases {
		for _, source := range []string{"stdin", "fifo"} {
			t.Run(signalCase.name+"/"+source, func(t *testing.T) {
				t.Parallel()
				_, set, _ := grpcFixtureSchema(t)
				protoset := writeGRPCFixtureProtoset(t, set)
				address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
				output := filepath.Join(t.TempDir(), "response.json")
				if err := os.WriteFile(output, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				args := []string{
					"grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset,
					"--timeout", "0", "--output", output,
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				command, stderr := newGRPCSignalHelperCommand(ctx, args...)

				var writer io.WriteCloser
				if source == "stdin" {
					stdin, err := command.StdinPipe()
					if err != nil {
						t.Fatal(err)
					}
					writer = stdin
				} else {
					fifo := filepath.Join(t.TempDir(), "request.fifo")
					if err := syscall.Mkfifo(fifo, 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--input", fifo)
					command, stderr = newGRPCSignalHelperCommand(ctx, args...)
				}
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				defer killGRPCSignalHelper(t, command)

				if source == "fifo" {
					fifo := args[len(args)-1]
					opened := make(chan struct {
						file *os.File
						err  error
					}, 1)
					go func() {
						file, err := os.OpenFile(fifo, os.O_WRONLY, 0)
						opened <- struct {
							file *os.File
							err  error
						}{file: file, err: err}
					}()
					select {
					case result := <-opened:
						if result.err != nil {
							t.Fatalf("open FIFO writer after reader handshake: %v", result.err)
						}
						writer = result.file
					case <-ctx.Done():
						t.Fatalf("gRPC process did not open FIFO input: %v", ctx.Err())
					}
				}
				t.Cleanup(func() {
					if writer != nil {
						if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
							t.Errorf("close %s input writer: %v", source, err)
						}
					}
				})
				writeDone := make(chan error, 1)
				go func() {
					_, err := writer.Write(bytes.Repeat([]byte{'x'}, grpcSignalInputSize))
					writeDone <- err
				}()
				select {
				case err := <-writeDone:
					if err != nil {
						t.Fatalf("fill blocking %s input: %v", source, err)
					}
				case <-ctx.Done():
					t.Fatalf("gRPC process did not drain %s input: %v", source, ctx.Err())
				}

				if err := command.Process.Signal(signalCase.signal); err != nil {
					t.Fatal(err)
				}
				waitForGRPCSignalExit(ctx, t, command, stderr, signalCase)
				calls, _, _ := record.snapshot()
				v1Calls, alphaCalls := record.reflectionCounts()
				if calls != 0 || v1Calls != 0 || alphaCalls != 0 || record.connectionCount() != 0 {
					t.Fatalf(
						"signal reached network: connections=%d calls=%d reflection v1=%d v1alpha=%d",
						record.connectionCount(), calls, v1Calls, alphaCalls,
					)
				}
				content, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				if string(content) != "preserve" {
					t.Fatalf("signal changed output to %q", content)
				}
			})
		}
	}
}

func TestGRPCExecuteSignalsCancelNetworkOperation(t *testing.T) {
	t.Parallel()

	for _, signalCase := range grpcSignalCases {
		t.Run(signalCase.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
			output := filepath.Join(t.TempDir(), "response.json")
			if err := os.WriteFile(output, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command, stderr := newGRPCSignalHelperCommand(
				ctx,
				"grpc", address, "--plaintext", "--timeout", "0", "--output", output,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer killGRPCSignalHelper(t, command)

			select {
			case <-record.reflectionStarted:
			case <-ctx.Done():
				t.Fatalf("gRPC process did not start reflection: %v", ctx.Err())
			}
			if err := command.Process.Signal(signalCase.signal); err != nil {
				t.Fatal(err)
			}
			waitForGRPCSignalExit(ctx, t, command, stderr, signalCase)
			select {
			case <-record.reflectionContextDone:
			case <-ctx.Done():
				t.Fatalf("signal did not cancel reflection context: %v", ctx.Err())
			}
			calls, _, _ := record.snapshot()
			if calls != 0 {
				t.Fatalf("signal invoked unary service %d times", calls)
			}
			content, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "preserve" {
				t.Fatalf("signal changed output to %q", content)
			}
		})
	}
}

func TestBareGRPCExecuteKeepsDefaultSIGINT(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command, stderr := newGRPCSignalHelperCommand(ctx, "grpc", address, "--plaintext", "--timeout", "0")
	command.Env = append(os.Environ(), grpcSignalBareExecuteEnvironment+"=1")
	require.NoError(t, command.Start())
	defer killGRPCSignalHelper(t, command)

	select {
	case <-record.reflectionStarted:
	case <-ctx.Done():
		t.Fatalf("bare Execute did not start gRPC reflection: %v", ctx.Err())
	}
	require.NoError(t, command.Process.Signal(syscall.SIGINT))
	waitErr := waitForGRPCSignalProcess(ctx, t, command)
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) {
		t.Fatalf("bare gRPC Execute exit = %v, want SIGINT termination; stderr=%q", waitErr, stderr.String())
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Fatalf("bare gRPC Execute status = %v, want default SIGINT termination; stderr=%q", status, stderr.String())
	}
}

func TestGRPCSecondSignalUsesDefaultDisposition(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	stderrReady := filepath.Join(t.TempDir(), "stderr-blocked")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command, _ := newGRPCSignalHelperCommand(
		ctx,
		"grpc", address, "--plaintext", "--timeout", "0", "--verbose",
	)
	command.Env = append(os.Environ(), grpcSignalBlockedStderrEnvironment+"="+stderrReady)
	require.NoError(t, command.Start())
	defer killGRPCSignalHelper(t, command)
	waitForGRPCSignalFile(ctx, t, stderrReady)

	select {
	case <-record.reflectionStarted:
	case <-ctx.Done():
		t.Fatalf("gRPC process did not start reflection: %v", ctx.Err())
	}
	require.NoError(t, command.Process.Signal(syscall.SIGINT))
	select {
	case <-record.reflectionContextDone:
	case <-ctx.Done():
		t.Fatalf("first SIGINT did not cancel reflection context: %v", ctx.Err())
	}
	waitForGRPCSignalFile(ctx, t, stderrReady+grpcSignalRootContextSuffix)
	require.NoError(t, command.Process.Signal(syscall.SIGINT))

	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("second SIGINT was swallowed while gRPC diagnostics remained blocked")
	}
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) {
		t.Fatalf("second SIGINT exit = %v, want default signal termination", waitErr)
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Fatalf("second SIGINT status = %v, want default SIGINT termination", status)
	}
}

func TestGRPCRequestFileCancellationClosesFIFOReaderBeforeProcessExit(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "request.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Filling the FIFO proves reads occurred; it does not measure cancellation latency.
	setupDeadline := time.NewTimer(10 * time.Second)
	defer setupDeadline.Stop()
	readResult := make(chan error, 1)
	go func() {
		_, err := grpccommand.ExportReadRequestFile(ctx, fifo, 2*grpcSignalInputSize)
		readResult <- err
	}()
	opened := make(chan struct {
		file *os.File
		err  error
	}, 1)
	go func() {
		file, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		opened <- struct {
			file *os.File
			err  error
		}{file: file, err: err}
	}()
	var writer *os.File
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatalf("open FIFO lifecycle writer after reader handshake: %v", result.err)
		}
		writer = result.file
	case <-setupDeadline.C:
		t.Fatal("gRPC request reader did not open FIFO")
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close FIFO lifecycle writer: %v", err)
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(writer, bytes.NewReader(bytes.Repeat([]byte{'x'}, grpcSignalInputSize)))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		require.NoError(t, err, "fill FIFO before cancellation: %v", err)
	case <-setupDeadline.C:
		t.Fatal("gRPC request reader did not drain FIFO input")
	}
	cancel()
	select {
	case err := <-readResult:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC request reader did not return after FIFO cancellation")
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		fd, openErr := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if errors.Is(openErr, syscall.ENXIO) {
			break
		}
		require.NoError(t, openErr, "probe FIFO reader closure: %v", openErr)
		require.NoError(t, syscall.Close(fd), "close FIFO reader probe")
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("owned FIFO reader remained open after cancellation")
		}
	}
}

func TestGRPCRequestFileReadsFIFOToEOFAndEnforcesLimit(t *testing.T) { //nolint:paralleltest // serializes kernel FIFO rendezvous under repeated signal tests
	const (
		chunkSize       = 32 * 1024
		configuredLimit = 4096
	)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for _, test := range []struct { //nolint:paralleltest // shares the bounded FIFO test context serially
		name    string
		size    int
		limit   int64
		wantErr bool
	}{
		{name: "empty EOF", limit: 64},
		{name: "normal payload", size: len(`{"text":"fifo"}`), limit: 64},
		{name: "chunk minus one", size: chunkSize - 1, limit: chunkSize + 2},
		{name: "chunk exact", size: chunkSize, limit: chunkSize + 2},
		{name: "chunk plus one", size: chunkSize + 1, limit: chunkSize + 2},
		{name: "limit minus one", size: configuredLimit - 1, limit: configuredLimit},
		{name: "limit exact", size: configuredLimit, limit: configuredLimit},
		{name: "limit plus one", size: configuredLimit + 1, limit: configuredLimit, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{'x'}, test.size)
			data, err := readGRPCFIFOToEOF(ctx, t, payload, test.limit)
			if test.wantErr {
				if !errors.Is(err, errGRPCMessageLimit) || data != nil {
					t.Fatalf("read %d bytes with limit %d = %d bytes, %v; want nil and errGRPCMessageLimit", test.size, test.limit, len(data), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("read %d FIFO bytes with limit %d: %v", test.size, test.limit, err)
			}
			if !bytes.Equal(data, payload) {
				t.Fatalf("FIFO data length/content = %d/%t, want %d/true", len(data), bytes.Equal(data, payload), len(payload))
			}
		})
	}
}

func readGRPCFIFOToEOF(ctx context.Context, t *testing.T, payload []byte, limit int64) ([]byte, error) {
	t.Helper()
	fifo := filepath.Join(t.TempDir(), "request.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	type readResult struct {
		err  error
		data []byte
	}
	result := make(chan readResult, 1)
	go func() {
		data, err := grpccommand.ExportReadRequestFile(ctx, fifo, limit)
		result <- readResult{data: data, err: err}
	}()
	opened := make(chan struct {
		file *os.File
		err  error
	}, 1)
	go func() {
		file, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		opened <- struct {
			file *os.File
			err  error
		}{file: file, err: err}
	}()
	var writer *os.File
	select {
	case openResult := <-opened:
		if openResult.err != nil {
			t.Fatalf("open FIFO writer after reader handshake: %v", openResult.err)
		}
		writer = openResult.file
	case read := <-result:
		t.Fatalf("gRPC request reader returned before FIFO writer opened: %v", read.err)
	case <-ctx.Done():
		t.Fatalf("gRPC request reader did not open FIFO: %v", ctx.Err())
	}
	t.Cleanup(func() {
		if writer != nil {
			if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Errorf("close FIFO payload writer: %v", err)
			}
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(writer, bytes.NewReader(payload))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		require.NoError(t, err, "write FIFO payload: %v", err)
	case read := <-result:
		closeErr := writer.Close()
		writer = nil
		select {
		case err := <-writeDone:
			if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.EPIPE) {
				t.Fatalf("finish FIFO payload write after reader completed: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("finish FIFO payload write after reader completed: %v", ctx.Err())
		}
		require.NoError(t, closeErr, "close FIFO writer after reader completed")
		if read.err == nil {
			t.Fatal("gRPC request reader completed successfully before FIFO EOF")
		}
		return read.data, read.err
	case <-ctx.Done():
		t.Fatalf("write FIFO payload: %v", ctx.Err())
	}
	closeErr := writer.Close()
	writer = nil
	select {
	case read := <-result:
		require.NoError(t, closeErr, "close FIFO writer")
		return read.data, read.err
	case <-ctx.Done():
		t.Fatalf("gRPC request reader did not finish at FIFO EOF: %v", ctx.Err())
		return nil, fmt.Errorf("read FIFO to EOF: %w", ctx.Err())
	}
}

func TestGRPCSignalExecuteHelperProcess(t *testing.T) { //nolint:paralleltest // helper branch replaces process arguments and exits
	marker := slices.Index(os.Args, grpcSignalHelperMarker)
	if marker < 0 {
		t.Parallel()
		return
	}
	os.Args = append([]string{"swys"}, os.Args[marker+1:]...)
	os.Exit(runGRPCSignalHelper())
}

func runGRPCSignalHelper() int {
	if os.Getenv(grpcSignalBareExecuteEnvironment) != "" {
		err := cmd.Execute()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "bare Execute: %v\n", err)
		}
		return grpcSignalCanceledExitCode
	}
	if path := os.Getenv(grpcSignalBlockedStderrEnvironment); path != "" {
		cleanup, err := blockGRPCSignalHelperStderr(path)
		if err != nil {
			return 90
		}
		defer cleanup()
	}
	ctx, stop := cmd.WithInterrupt(context.Background())
	defer stop()
	if path := os.Getenv(grpcSignalBlockedStderrEnvironment); path != "" {
		go func() {
			<-ctx.Done()
			_ = os.WriteFile(path+grpcSignalRootContextSuffix, []byte("ready"), 0o600) //nolint:errcheck // parent timeout reports failure
		}()
	}
	err := cmd.ExecuteContext(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "swys: %v\n", err)
	}
	return cmd.ExitCode(err)
}

func blockGRPCSignalHelperStderr(markerPath string) (func(), error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create blocked stderr pipe: %w", err)
	}
	closePipe := func() {
		_ = writer.Close() //nolint:errcheck // helper process is terminating
		_ = reader.Close() //nolint:errcheck // helper process is terminating
	}
	fd := int(writer.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		closePipe()
		return nil, fmt.Errorf("make stderr pipe nonblocking: %w", err)
	}
	filler := bytes.Repeat([]byte{'x'}, 32*1024)
	for {
		_, writeErr := syscall.Write(fd, filler)
		if writeErr == nil {
			continue
		}
		if !errors.Is(writeErr, syscall.EAGAIN) {
			closePipe()
			return nil, fmt.Errorf("fill stderr pipe: %w", writeErr)
		}
		break
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		closePipe()
		return nil, fmt.Errorf("make stderr pipe blocking: %w", err)
	}
	original := os.Stderr
	os.Stderr = writer
	if err := os.WriteFile(markerPath, []byte("ready"), 0o600); err != nil {
		os.Stderr = original
		closePipe()
		return nil, fmt.Errorf("mark blocked stderr ready: %w", err)
	}
	return func() {
		os.Stderr = original
		closePipe()
	}, nil
}

func newGRPCSignalHelperCommand(ctx context.Context, args ...string) (*exec.Cmd, *bytes.Buffer) {
	processArgs := []string{"-test.run=^TestGRPCSignalExecuteHelperProcess$", "--", grpcSignalHelperMarker}
	processArgs = append(processArgs, args...)
	command := exec.CommandContext(ctx, os.Args[0], processArgs...)
	stderr := &bytes.Buffer{}
	command.Stdout = io.Discard
	command.Stderr = stderr
	return command, stderr
}

func waitForGRPCSignalExit(
	ctx context.Context,
	t *testing.T,
	command *exec.Cmd,
	stderr *bytes.Buffer,
	signalCase grpcSignalCase,
) {
	t.Helper()
	waitErr := waitForGRPCSignalProcess(ctx, t, command)
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) {
		t.Fatalf("gRPC process exit = %v, want status %d; stderr=%q", waitErr, signalCase.status, stderr.String())
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("gRPC process status has type %T, want syscall.WaitStatus", exitError.Sys())
	}
	if status.Signaled() || status.ExitStatus() != signalCase.status {
		t.Fatalf(
			"gRPC process signaled=%t signal=%v exit=%d, want normal exit %d; stderr=%q",
			status.Signaled(), status.Signal(), status.ExitStatus(), signalCase.status, stderr.String(),
		)
	}
	wantDiagnostic := "swys: " + signalCase.message
	if strings.TrimSpace(stderr.String()) != wantDiagnostic {
		t.Fatalf("gRPC process stderr = %q, want %q", stderr.String(), wantDiagnostic)
	}
}

func waitForGRPCSignalProcess(ctx context.Context, t *testing.T, command *exec.Cmd) error {
	t.Helper()
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	select {
	case err := <-exited:
		return err
	case <-ctx.Done():
		t.Fatalf("wait for signal helper: %v", ctx.Err())
		return fmt.Errorf("wait for signal helper: %w", ctx.Err())
	}
}

func waitForGRPCSignalFile(ctx context.Context, t *testing.T, path string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		contents, err := os.ReadFile(path)
		if err == nil && len(contents) != 0 {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for signal marker %s: %v", filepath.Base(path), ctx.Err())
		}
	}
}

func killGRPCSignalHelper(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if command.ProcessState != nil && command.ProcessState.Exited() {
		return
	}
	if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("kill signal helper: %v", err)
	}
}
