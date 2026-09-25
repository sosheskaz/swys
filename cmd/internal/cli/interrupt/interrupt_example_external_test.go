package interrupt_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/interrupt"
)

var errExampleCommandFailed = errors.New("test command failed")

func ExampleExitCode() {
	fmt.Println(interrupt.ExitCode(nil))
	fmt.Println(interrupt.ExitCode(errExampleCommandFailed))
	fmt.Println(interrupt.ExitCode(interrupt.NewError(os.Interrupt)))
	fmt.Println(interrupt.ExitCode(interrupt.NewError(syscall.SIGTERM)))
	// Output:
	// 0
	// 1
	// 130
	// 143
}

func TestInterruptExamples(t *testing.T) {
	t.Parallel()

	t.Run("Ctrl-C stops a listener waiting for a peer", func(t *testing.T) {
		t.Parallel()
		run := startInterruptibleCommand(t, strings.NewReader(""), "net", "listen", "127.0.0.1:0", "--verbose")
		readExampleListeningAddress(t, run.stderr, "listening tcp ")
		drainExampleStderr(run.stderr)

		run.signals <- os.Interrupt

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
	})

	t.Run("SIGTERM stops an established relay", func(t *testing.T) {
		t.Parallel()
		stdin, stdinWriter := io.Pipe()
		t.Cleanup(func() { _ = stdinWriter.Close() }) //nolint:errcheck // test cleanup is best effort
		run := startInterruptibleCommand(t, stdin, "net", "listen", "127.0.0.1:0", "--verbose")
		address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
		drainExampleStderr(run.stderr)
		connection := dialListenTestTCP(t, address)
		t.Cleanup(func() { closeListenTestTCP(t, connection) })

		run.signals <- syscall.SIGTERM

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "terminated", 143)
	})

	t.Run("Ctrl-C stops a hash waiting on stdin", func(t *testing.T) {
		t.Parallel()
		stdin, stdinWriter := io.Pipe()
		t.Cleanup(func() { _ = stdinWriter.Close() }) //nolint:errcheck // test cleanup is best effort
		run := startInterruptibleCommand(t, stdin, "hash", "sha256")

		run.signals <- os.Interrupt

		requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
	})

	t.Run("a failure without a signal keeps exit status 1", func(t *testing.T) {
		t.Parallel()
		run := startInterruptibleCommand(t, strings.NewReader(""), "hash", "sha256", "--input", "/nonexistent/npc-input")

		err := waitForInterruptedRun(t, run.done)

		if err == nil || interrupt.ExitCode(err) != 1 {
			t.Fatalf("error = %v, exit code %d, want failure with exit code 1", err, interrupt.ExitCode(err))
		}
	})
}

type interruptibleRun struct {
	signals chan<- os.Signal
	stderr  *bufio.Reader
	done    <-chan error
}

// startInterruptibleCommand runs the root command under the same context
// wiring as ExecuteContext, with an injected signal source.
func startInterruptibleCommand(t *testing.T, input io.Reader, args ...string) interruptibleRun {
	t.Helper()
	signals := make(chan os.Signal, 1)
	ctx, stop, _ := interrupt.NewControlledContext(t.Context(), signals)
	t.Cleanup(stop)

	root := rootcmd.NewCommand()
	root.SetArgs(args)
	root.SetIn(input)
	root.SetOut(io.Discard)
	stderrReader, stderrWriter := io.Pipe()
	root.SetErr(stderrWriter)

	done := make(chan error, 1)
	go func() {
		root.SetContext(ctx)
		err := interrupt.Attribute(ctx, commandio.Execute(root))
		done <- errors.Join(err, stderrWriter.Close())
	}()
	return interruptibleRun{signals: signals, stderr: bufio.NewReader(stderrReader), done: done}
}

func waitForInterruptedRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("command did not stop")
		return nil
	}
}

func requireInterrupted(t *testing.T, err error, message string, code int) {
	t.Helper()
	if err == nil || err.Error() != message {
		t.Fatalf("error = %v, want %q", err, message)
	}
	if got := interrupt.ExitCode(err); got != code {
		t.Fatalf("exit code = %d, want %d", got, code)
	}
}

func TestInterruptStopsHTTPRequestBlockedOnStdinBody(t *testing.T) {
	t.Parallel()
	// The server accepts through its backlog and never answers.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
	stdin := &blockingStdin{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(stdin.release) })
	run := startInterruptibleCommand(t, stdin, "http", "-X", "POST", "http://"+listener.Addr().String()+"/")
	waitForSignal(t, stdin.entered, "request never read its stdin body")

	run.signals <- os.Interrupt

	requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
}

// blockingStdin behaves like a blocking file descriptor: Close does not wake a pending Read.
type blockingStdin struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (stdin *blockingStdin) Read([]byte) (int, error) {
	stdin.once.Do(func() { close(stdin.entered) })
	<-stdin.release
	return 0, io.EOF
}

func (*blockingStdin) Close() error { return nil }

func drainExampleStderr(reader io.Reader) {
	go func() {
		_, _ = io.Copy(io.Discard, reader) //nolint:errcheck // this fixture only drains diagnostics until command exit
	}()
}

func readExampleListeningAddress(t *testing.T, reader *bufio.Reader, prefix string) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read listening diagnostic: %v", err)
	}
	line = strings.TrimSpace(line)
	address, found := strings.CutPrefix(line, prefix)
	if !found {
		t.Fatalf("listening diagnostic = %q, want prefix %q", line, prefix)
	}
	return address
}

func dialListenTestTCP(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		closeListenTestTCP(t, connection)
		t.Fatalf("connection type = %T, want *net.TCPConn", connection)
	}
	return tcpConnection
}

func closeListenTestTCP(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatal(failure)
	}
}
