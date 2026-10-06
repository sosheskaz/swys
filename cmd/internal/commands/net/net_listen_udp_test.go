package net_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/netconn"
)

func TestNetListenUDPFlagAndAddressContract(t *testing.T) {
	t.Parallel()
	netListenUDPCmd := newNetListenTestCommand(t, "udp")
	assert.Equal(t, "0s", netListenUDPCmd.Flags().Lookup("connect-timeout").DefValue, "timeout default")
	for _, name := range []string{"wait", "close-write"} {
		assert.NotNil(t, netListenUDPCmd.Flags().Lookup(name), "net listen union has no --%s flag", name)
	}
	stdout, _, err := executeRootStreams(t, "net", "listen", "--udp", "--help")
	require.NoError(t, err)
	assert.Contains(t, stdout, "net listen [host:]port")
	for _, address := range []string{"localhost:", ":", "localhost", "http", "65536"} {
		_, _, err := executeRootStreams(t, "net", "listen", "--udp", address)
		require.ErrorIs(t, err, errInvalidHostPort)
	}
	_, _, err = executeRootStreams(t, "net", "listen", "--udp", "0", "--connect-timeout", "-1s")
	require.ErrorIs(t, err, errInvalidNetworkFlags)
}

func TestNetListenUDPPositiveFirstDatagramTimeoutClosesSocket(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("response"),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--connect-timeout", "30ms",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	require.ErrorIs(t, <-run.done, context.DeadlineExceeded)
	<-remainingStderr

	resolved, err := net.ResolveUDPAddr("udp", address)
	require.NoError(t, err)
	rebound, err := net.ListenUDP("udp", resolved)
	require.NoError(t, err, "rebind UDP listener after timeout: %v", err)
	closeUDPTest(t, rebound)
}

func TestNetListenUDPAcceptsColonPortCompatibility(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(
		t,
		"net", "listen", "--udp", ":0",
		"--connect-timeout", "25ms",
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestNetListenUDPIPv6Loopback(t *testing.T) {
	t.Parallel()
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	closeUDPTest(t, probe)

	run := startExampleListenCommand(
		t,
		strings.NewReader("response"),
		"net", "listen", "--udp", "[::1]:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	peer, err := net.ResolveUDPAddr("udp6", address)
	require.NoError(t, err)
	client, err := net.DialUDP("udp6", nil, peer)
	require.NoError(t, err)
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		closeUDPTest(t, client)
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, client) })
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	read, err := client.Read(buffer)
	require.NoError(t, err)
	if got := string(buffer[:read]); got != "response" {
		t.Fatalf("response = %q, want IPv6 listener response", got)
	}
	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want IPv6 client request", got)
	}
	<-remainingStderr
}

func TestNetListenUDPBindFailure(t *testing.T) {
	t.Parallel()
	occupied := listenUDPTest(t)
	_, _, err := executeRootStreams(
		t,
		"net", "listen", "--udp", occupied.LocalAddr().String(),
		"--connect-timeout", "25ms",
	)
	require.ErrorContains(t, err, "listen on UDP endpoint")
}

func TestNetListenUDPRelaysEncodedDatagrams(t *testing.T) {
	t.Parallel()
	response := base64.StdEncoding.EncodeToString([]byte("listener response"))
	run := startExampleListenCommand(
		t,
		strings.NewReader(response),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--input-encoding", "base64",
		"--encoding", "base64",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	client := dialUDPListenTest(t, address)
	if _, err := client.Write([]byte("client request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	read, err := client.Read(buffer)
	require.NoError(t, err)
	if got := string(buffer[:read]); got != "listener response" {
		t.Fatalf("client response = %q, want decoded listener input", got)
	}
	require.NoError(t, <-run.done)
	decoded, err := base64.StdEncoding.DecodeString(run.stdout.String())
	require.NoError(t, err)
	if got := string(decoded); got != "client request" {
		t.Fatalf("listener output = %q, want encoded client request", got)
	}
	<-remainingStderr
}

func TestNetListenUDPFinalizesEncodedRequestBeforeReadingResponse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		encoding string
		want     string
	}{
		{encoding: "base64", want: "eA=="},
		{encoding: "base32", want: "PA======"},
	}
	for _, test := range tests {
		t.Run(test.encoding, func(t *testing.T) {
			t.Parallel()
			responseReader, responseWriter := io.Pipe()
			t.Cleanup(func() {
				if err := responseReader.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("close response reader: %v", err)
				}
				if err := responseWriter.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("close response writer: %v", err)
				}
			})
			outputPath := filepath.Join(t.TempDir(), "request.txt")
			run := startExampleListenCommand(
				t,
				responseReader,
				"net", "listen", "--udp", "127.0.0.1:0",
				"--encoding", test.encoding,
				"--output", outputPath,
				"--verbose",
			)
			address := readExampleListeningAddress(t, run.stderr, "listening udp ")
			client := dialUDPListenTest(t, address)
			if _, err := client.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			line, err := run.stderr.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			assert.Contains(t, line, "received udp ")
			remainingStderr := drainExampleStderr(run.stderr)

			waitForUDPOutput(t, outputPath, test.want)
			if err := responseWriter.Close(); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1)
			if read, err := client.Read(buffer); err != nil {
				t.Fatal(err)
			} else if read != 0 {
				t.Fatalf("response length = %d, want zero", read)
			}
			if err := <-run.done; err != nil {
				t.Fatal(err)
			}
			<-remainingStderr
		})
	}
}

func TestNetListenUDPCancellationWhileReadingResponseClosesSocket(t *testing.T) {
	t.Parallel()
	responseReader, responseWriter := io.Pipe()
	t.Cleanup(func() {
		if err := responseReader.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close response reader: %v", err)
		}
		if err := responseWriter.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close response writer: %v", err)
		}
	})
	run := startExampleListenCommand(
		t,
		responseReader,
		"net", "listen", "--udp", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	client := dialUDPListenTest(t, address)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	line, err := run.stderr.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, line, "received udp ")
	remainingStderr := drainExampleStderr(run.stderr)

	run.cancel()
	select {
	case err := <-run.done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("listener did not stop after cancellation while reading response")
	}
	<-remainingStderr

	resolved, err := net.ResolveUDPAddr("udp", address)
	require.NoError(t, err)
	rebound, err := net.ListenUDP("udp", resolved)
	require.NoError(t, err, "rebind UDP listener after cancellation: %v", err)
	closeUDPTest(t, rebound)
}

func TestNetListenUDPTimeoutOnlyCoversSetupAndFirstDatagram(t *testing.T) {
	t.Parallel()
	responseReader, responseWriter := io.Pipe()
	t.Cleanup(func() {
		if err := responseReader.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close delayed response reader: %v", err)
		}
		if err := responseWriter.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close delayed response writer: %v", err)
		}
	})
	run := startExampleListenCommand(
		t,
		responseReader,
		"net", "listen", "--udp", "127.0.0.1:0",
		"--connect-timeout", "1s",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	client := dialUDPListenTest(t, address)
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if _, err := io.WriteString(responseWriter, "delayed response"); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, responseWriter.Close())
	buffer := make([]byte, 64)
	read, err := client.Read(buffer)
	require.NoError(t, err)
	if got := string(buffer[:read]); got != "delayed response" {
		t.Fatalf("response = %q, want response after setup timeout elapsed", got)
	}
	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want request", got)
	}
	<-remainingStderr
}

func TestNetListenUDPRespondsOnlyToFirstPeer(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("response"),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	first := dialUDPListenTest(t, address)
	second := dialUDPListenTest(t, address)
	if _, err := first.Write([]byte("first request")); err != nil {
		t.Fatal(err)
	}
	line, err := run.stderr.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, line, "received udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	if _, err := second.Write([]byte("second request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	read, err := first.Read(buffer)
	require.NoError(t, err)
	if got := string(buffer[:read]); got != "response" {
		t.Fatalf("first peer response = %q, want response", got)
	}
	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "first request" {
		t.Fatalf("listener output = %q, want first peer request", got)
	}
	if _, err := second.Read(buffer); err == nil {
		t.Fatal("second peer unexpectedly received a response")
	}
	<-remainingStderr
}

func TestNetListenUDPSendsAndReceivesZeroLengthDatagrams(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	client := dialUDPListenTest(t, address)
	if _, err := client.Write(nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	read, err := client.Read(buffer)
	require.NoError(t, err)
	if read != 0 {
		t.Fatalf("response length = %d, want zero", read)
	}
	require.NoError(t, <-run.done)
	if run.stdout.Len() != 0 {
		t.Fatalf("listener output length = %d, want zero", run.stdout.Len())
	}
	<-remainingStderr
}

func TestNetListenUDPRejectsOversizedResponseWithoutSending(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		bytes.NewReader(make([]byte, netconn.MaxUDPPayloadSize+1)),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	client := dialUDPListenTest(t, address)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := <-run.done; !errors.Is(err, netconn.ErrDatagramTooLarge) {
		t.Fatalf("error = %v, want ErrDatagramTooLarge", err)
	}
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want preserved request", got)
	}
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("client received a response after oversized input rejection")
	}
	<-remainingStderr
}

func waitForUDPOutput(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got, err := os.ReadFile(path)
		if err == nil && string(got) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("output before response input = %q, %v; want %q", got, err, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func dialUDPListenTest(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err)
	connection, err := net.DialUDP("udp", nil, peer)
	require.NoError(t, err)
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		closeUDPTest(t, connection)
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, connection) })
	return connection
}
