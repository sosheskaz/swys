package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var errListenDiagnosticOutput = errors.New("diagnostic output failed")

func TestNetListenTCPDefaultsToUnlimitedAcceptWait(t *testing.T) {
	if got := netListenTCPCmd.Flags().Lookup("timeout").DefValue; got != "0s" {
		t.Fatalf("listen timeout default = %q, want 0s", got)
	}
	if got := netConnectTCPCmd.Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Fatalf("connect timeout default = %q, want unchanged 10s", got)
	}
}

func TestNetListenTCPPositiveAcceptTimeout(t *testing.T) {
	_, _, err := executeRootStreams(
		t,
		"net", "listen", "tcp", "127.0.0.1:0",
		"--timeout", "30ms",
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "accept TCP connection on") {
		t.Fatalf("error = %v, want accept operation context", err)
	}
}

func TestNetListenTCPRejectsMissingHost(t *testing.T) {
	_, _, err := executeRootStreams(t, "net", "listen", "tcp", ":8080")
	if !errors.Is(err, errInvalidHostPort) {
		t.Fatalf("error = %v, want errInvalidHostPort", err)
	}
}

func TestNetListenTCPBindFailure(t *testing.T) {
	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close occupied listener: %v", err)
		}
	})
	_, _, err = executeRootStreams(t, "net", "listen", "tcp", occupied.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "listen on TCP endpoint") {
		t.Fatalf("error = %v, want TCP bind failure", err)
	}
}

func TestNetListenTCPDiagnosticWriteFailures(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close diagnostic listener: %v", err)
		}
	})
	want := errListenDiagnosticOutput
	if err := writeTCPListeningDetails(failingWriter{err: want}, listener); !errors.Is(err, want) {
		t.Fatalf("listening detail error = %v, want output failure", err)
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- connection
		acceptErr <- err
	}()
	client := dialListenTestTCP(t, listener.Addr().String())
	t.Cleanup(func() { closeListenTestTCP(t, client) })
	server := <-accepted
	if err := <-acceptErr; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeListenTestTCP(t, server) })
	if err := writeTCPAcceptedDetails(failingWriter{err: want}, server); !errors.Is(err, want) {
		t.Fatalf("accepted detail error = %v, want output failure", err)
	}
}

func TestNetListenTCPRelaysEncodedPayload(t *testing.T) {
	listenerInput := base64.StdEncoding.EncodeToString([]byte("listener payload"))
	run := startExampleListenCommand(
		t,
		strings.NewReader(listenerInput),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--input-encoding", "base64",
		"--encoding", "base64",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	if _, err := io.WriteString(connection, "client payload"); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("listener payload"))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	closeListenTestTCP(t, connection)
	if got := string(received); got != "listener payload" {
		t.Fatalf("client received %q, want decoded listener payload", got)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(run.stdout.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decoded); got != "client payload" {
		t.Fatalf("decoded listener output = %q, want client payload", got)
	}
	if got := <-stderr; !strings.Contains(got, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted diagnostic", got)
	}
}

func TestNetListenTCPTimeoutOnlyCoversSetup(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader("request"),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--timeout", "50ms",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(connection, request); err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("client received %q, want request", request)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := io.WriteString(connection, "delayed response"); err != nil {
		t.Fatal(err)
	}
	closeListenTestTCP(t, connection)
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "delayed response" {
		t.Fatalf("listener output = %q, want delayed response", got)
	}
	<-stderr
}

func TestNetListenTCPCloseWriteSignalsInputEOF(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader("request"),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--close-write",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	request, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("client received %q, want request before EOF", request)
	}
	if _, err := io.WriteString(connection, "response"); err != nil {
		t.Fatal(err)
	}
	closeListenTestTCP(t, connection)
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "response" {
		t.Fatalf("listener output = %q, want response", got)
	}
	<-stderr
}

func TestNetListenTCPDrainTimeoutPreservesPartialOutput(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--verbose",
		"--wait", "50ms",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	if _, err := io.WriteString(connection, "partial response"); err != nil {
		t.Fatal(err)
	}
	if err := <-run.done; !errors.Is(err, netconn.ErrDrainTimeout) {
		t.Fatalf("error = %v, want drain timeout", err)
	}
	if got := run.stdout.String(); got != "partial response" {
		t.Fatalf("listener output = %q, want preserved partial response", got)
	}
	closeListenTestTCP(t, connection)
	<-stderr
}

func TestNetListenTCPZeroWaitDrainsUntilPeerCloses(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--verbose",
		"--wait", "0",
	)
	address := readExampleListeningTCPAddress(t, run.stderr)
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	time.Sleep(75 * time.Millisecond)
	if _, err := io.WriteString(connection, "late response"); err != nil {
		t.Fatal(err)
	}
	closeListenTestTCP(t, connection)
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "late response" {
		t.Fatalf("listener output = %q, want late response", got)
	}
	<-stderr
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
