package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var (
	errUDPTestDiagnostic = errors.New("UDP diagnostic failed")
	errUDPTestOutput     = errors.New("UDP output failed")
)

func TestNetConnectUDPFlagContract(t *testing.T) {
	t.Parallel()
	netConnectUDPCmd := newNetConnectUDPCmd()
	if got := netConnectUDPCmd.Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Fatalf("timeout default = %q, want 10s", got)
	}
	if got := netConnectUDPCmd.Flags().Lookup("wait").DefValue; got != "5s" {
		t.Fatalf("wait default = %q, want 5s", got)
	}
	if flag := netConnectUDPCmd.Flags().Lookup("close-write"); flag != nil {
		t.Fatalf("UDP connector unexpectedly exposes --%s", flag.Name)
	}
	for _, args := range [][]string{
		{"net", "connect", "udp", "127.0.0.1:53", "--timeout", "-1s"},
		{"net", "connect", "udp", "127.0.0.1:53", "--wait", "-1s"},
	} {
		if _, _, err := executeRootStreams(t, args...); !errors.Is(err, errInvalidNetworkFlags) {
			t.Fatalf("args %v error = %v, want errInvalidNetworkFlags", args, err)
		}
	}
}

func TestNetConnectUDPRequiresHostAndPort(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"53", ":53", "localhost:", "localhost"} {
		_, _, err := executeRootStreams(t, "net", "connect", "udp", address)
		if !errors.Is(err, errInvalidHostPort) {
			t.Fatalf("address %q error = %v, want errInvalidHostPort", address, err)
		}
	}
}

func TestNetConnectUDPResponseTimeout(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	requestRead := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, _, err := listener.ReadFromUDP(buffer)
		requestRead <- err
	}()

	_, _, err := executeRootStreamsWithInput(
		t,
		strings.NewReader("request"),
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--wait", "30ms",
	)
	if !errors.Is(err, netconn.ErrUDPResponseTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want UDP response and context deadline errors", err)
	}
	if readErr := <-requestRead; readErr != nil {
		t.Fatal(readErr)
	}
}

func TestNetConnectUDPZeroWaitWaitsIndefinitelyForFirstResponse(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		time.Sleep(75 * time.Millisecond)
		_, writeErr := listener.WriteToUDP([]byte("response"), peer)
		serverDone <- writeErr
	}()

	stdout, _, err := executeRootStreamsWithInput(
		t,
		strings.NewReader("request"),
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--wait", "0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want delayed response", stdout)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestNetConnectUDPExitsAfterFirstResponseDatagram(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, firstErr := listener.WriteToUDP([]byte("first"), peer)
		_, secondErr := listener.WriteToUDP([]byte("second"), peer)
		serverDone <- errors.Join(firstErr, secondErr)
	}()

	stdout, _, err := executeRootStreamsWithInput(
		t,
		strings.NewReader("request"),
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "first" {
		t.Fatalf("response = %q, want only first datagram", stdout)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestNetConnectUDPSendsAndReceivesZeroLengthDatagrams(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	requestLength := make(chan int, 1)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		read, peer, readErr := listener.ReadFromUDP(buffer)
		requestLength <- read
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := listener.WriteToUDP(nil, peer)
		serverDone <- writeErr
	}()

	stdout, _, err := executeRootStreamsWithInput(
		t,
		strings.NewReader(""),
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Fatalf("response = %q, want empty datagram", stdout)
	}
	if got := <-requestLength; got != 0 {
		t.Fatalf("request length = %d, want zero", got)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestNetConnectUDPRejectsOversizedInputBeforeSending(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	if err := listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	_, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(make([]byte, netconn.MaxUDPPayloadSize+1)),
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	if !errors.Is(err, netconn.ErrDatagramTooLarge) {
		t.Fatalf("error = %v, want ErrDatagramTooLarge", err)
	}
	buffer := make([]byte, 1)
	if _, _, readErr := listener.ReadFromUDP(buffer); readErr == nil {
		t.Fatal("server received a datagram after oversized input rejection")
	}
}

func TestNetConnectUDPCancellationWhileReadingInputClosesSocket(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	input, inputWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	rootCmd := newRootCmd()
	rootCmd.SetContext(ctx)
	rootCmd.SetArgs([]string{
		"net", "connect", "udp", listener.LocalAddr().String(),
		"--verbose",
	})
	rootCmd.SetIn(input)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(stderrWriter)
	t.Cleanup(func() {
		cancel()
		if err := input.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close connector input: %v", err)
		}
		if err := inputWriter.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close connector input writer: %v", err)
		}
		if err := stderrReader.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close connector stderr: %v", err)
		}
	})
	done := make(chan error, 1)
	go func() {
		command, runErr := rootCmd.ExecuteC()
		runErr = errors.Join(runErr, closeCommandIO(command), stderrWriter.Close())
		done <- runErr
	}()

	line, err := bufio.NewReader(stderrReader).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	connection, found := strings.CutPrefix(strings.TrimSpace(line), "connected udp ")
	if !found {
		t.Fatalf("diagnostic = %q, want connected UDP endpoints", line)
	}
	localAddress, _, found := strings.Cut(connection, " -> ")
	if !found {
		t.Fatalf("diagnostic = %q, want local and remote UDP endpoints", line)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connector did not stop after cancellation while reading input")
	}

	resolved, err := net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp", resolved)
	if err != nil {
		t.Fatalf("rebind connector socket after cancellation: %v", err)
	}
	closeUDPTest(t, rebound)
}

func TestExchangeUDPDatagramReturnsOutputFailure(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := listener.WriteToUDP([]byte("response"), peer)
		serverDone <- writeErr
	}()
	connection, err := netconn.DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, connection) })
	want := errUDPTestOutput
	err = exchangeUDPDatagram(t.Context(), connection, strings.NewReader("request"), failingWriter{err: want}, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want output failure", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWriteUDPConnectionDetailsReturnsOutputFailure(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	connection, err := netconn.DialUDP(t.Context(), listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, connection) })
	want := errUDPTestDiagnostic
	if err := writeUDPConnectionDetails(failingWriter{err: want}, connection); !errors.Is(err, want) {
		t.Fatalf("error = %v, want diagnostic failure", err)
	}
}

func listenUDPTest(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, listener) })
	return listener
}

func closeUDPTest(t *testing.T, connection io.Closer) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close UDP test socket: %v", err)
	}
}
