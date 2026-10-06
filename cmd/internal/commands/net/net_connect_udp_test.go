package net_test

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/netconn"
)

func TestNetConnectUDPRejectsNegativeDurations(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"net", "connect", "--udp", "127.0.0.1:53", "--connect-timeout", "-1s"},
		{"net", "connect", "--udp", "127.0.0.1:53", "--wait", "-1s"},
	} {
		_, _, err := executeRootStreams(t, args...)
		require.ErrorIs(t, err, errInvalidNetworkFlags, "args %v", args)
	}
}

func TestNetConnectUDPRequiresHostAndPort(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"53", ":53", "localhost:", "localhost"} {
		_, _, err := executeRootStreams(t, "net", "connect", "--udp", address)
		require.ErrorIs(t, err, errInvalidHostPort)
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
		"net", "connect", "--udp", listener.LocalAddr().String(),
		"--wait", "30ms",
	)
	require.ErrorIs(t, err, netconn.ErrUDPResponseTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, <-requestRead)
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
		"net", "connect", "--udp", listener.LocalAddr().String(),
		"--wait", "0",
	)
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	require.NoError(t, <-serverDone)
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
		"net", "connect", "--udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Equal(t, "first", stdout)
	require.NoError(t, <-serverDone)
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
		"net", "connect", "--udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	require.Zero(t, <-requestLength, "request length")
	require.NoError(t, <-serverDone)
}

func TestNetConnectUDPRejectsOversizedInputBeforeSending(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	_, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(make([]byte, netconn.MaxUDPPayloadSize+1)),
		"net", "connect", "--udp", listener.LocalAddr().String(),
		"--wait", "1s",
	)
	require.ErrorIs(t, err, netconn.ErrDatagramTooLarge)
	buffer := make([]byte, 1)
	if _, _, readErr := listener.ReadFromUDP(buffer); readErr == nil {
		t.Fatal("server received a datagram after oversized input rejection")
	}
}

func TestNetConnectUDPCancellationWhileReadingInput(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	input, inputWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	rootCmd := newRootCmd()
	rootCmd.SetContext(ctx)
	rootCmd.SetArgs([]string{
		"net", "connect", "--udp", listener.LocalAddr().String(),
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
		runErr := errors.Join(commandio.Execute(rootCmd), stderrWriter.Close())
		done <- runErr
	}()

	line, err := bufio.NewReader(stderrReader).ReadString('\n')
	require.NoError(t, err)
	connection, found := strings.CutPrefix(strings.TrimSpace(line), "connected udp ")
	if !found {
		t.Fatalf("diagnostic = %q, want connected UDP endpoints", line)
	}
	_, _, found = strings.Cut(connection, " -> ")
	if !found {
		t.Fatalf("diagnostic = %q, want local and remote UDP endpoints", line)
	}
	waitForUDPInputRead(t, inputWriter, done)

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("connector did not stop after cancellation while reading input")
	}
}

func listenUDPTest(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { closeUDPTest(t, listener) })
	return listener
}

func closeUDPTest(t *testing.T, connection io.Closer) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close UDP test socket: %v", err)
	}
}
