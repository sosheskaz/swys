package cmd

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

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

func TestNetListenUDPFlagAndAddressContract(t *testing.T) {
	t.Parallel()
	netListenUDPCmd := newNetListenTestCommand(t, "udp")
	if got := netListenUDPCmd.Flags().Lookup("timeout").DefValue; got != "0s" {
		t.Fatalf("timeout default = %q, want 0s", got)
	}
	for _, name := range []string{"wait", "close-write"} {
		if flag := netListenUDPCmd.Flags().Lookup(name); flag == nil {
			t.Fatalf("net listen union has no --%s flag", name)
		}
	}
	stdout, _, err := executeRootStreams(t, "net", "listen", "--udp", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "net listen [host:]port") {
		t.Fatalf("help = %q, want optional-host usage", stdout)
	}
	for _, address := range []string{"localhost:", ":", "localhost", "http", "65536"} {
		_, _, err := executeRootStreams(t, "net", "listen", "--udp", address)
		if !errors.Is(err, errInvalidHostPort) {
			t.Fatalf("address %q error = %v, want errInvalidHostPort", address, err)
		}
	}
	_, _, err = executeRootStreams(t, "net", "listen", "--udp", "0", "--timeout", "-1s")
	if !errors.Is(err, errInvalidNetworkFlags) {
		t.Fatalf("negative timeout error = %v, want errInvalidNetworkFlags", err)
	}
}

func TestNetListenUDPPositiveFirstDatagramTimeoutClosesSocket(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("response"),
		"net", "listen", "--udp", "127.0.0.1:0",
		"--timeout", "30ms",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	if err := <-run.done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want first-datagram deadline", err)
	}
	<-remainingStderr

	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp", resolved)
	if err != nil {
		t.Fatalf("rebind UDP listener after timeout: %v", err)
	}
	closeUDPTest(t, rebound)
}

func TestNetListenUDPAcceptsColonPortCompatibility(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(
		t,
		"net", "listen", "--udp", ":0",
		"--timeout", "25ms",
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline after accepting :port", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp6", nil, peer)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:read]); got != "response" {
		t.Fatalf("response = %q, want IPv6 listener response", got)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
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
		"--timeout", "25ms",
	)
	if err == nil || !strings.Contains(err.Error(), "listen on UDP endpoint") {
		t.Fatalf("error = %v, want UDP bind failure", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:read]); got != "listener response" {
		t.Fatalf("client response = %q, want decoded listener input", got)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(run.stdout.String())
	if err != nil {
		t.Fatal(err)
	}
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
			if !strings.Contains(line, "received udp ") {
				t.Fatalf("diagnostic = %q, want received datagram", line)
			}
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
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "received udp ") {
		t.Fatalf("diagnostic = %q, want received datagram", line)
	}
	remainingStderr := drainExampleStderr(run.stderr)

	run.cancel()
	select {
	case err := <-run.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not stop after cancellation while reading response")
	}
	<-remainingStderr

	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp", resolved)
	if err != nil {
		t.Fatalf("rebind UDP listener after cancellation: %v", err)
	}
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
		"--timeout", "1s",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	client := dialUDPListenTest(t, address)
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if _, err := io.WriteString(responseWriter, "delayed response"); err != nil {
		t.Fatal(err)
	}
	if err := responseWriter.Close(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	read, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:read]); got != "delayed response" {
		t.Fatalf("response = %q, want response after setup timeout elapsed", got)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "received udp ") {
		t.Fatalf("diagnostic = %q, want received datagram", line)
	}
	remainingStderr := drainExampleStderr(run.stderr)
	if _, err := second.Write([]byte("second request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	read, err := first.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:read]); got != "response" {
		t.Fatalf("first peer response = %q, want response", got)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if read != 0 {
		t.Fatalf("response length = %d, want zero", read)
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
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

func TestRespondUDPDatagramReturnsOutputFailureBeforeSending(t *testing.T) {
	t.Parallel()
	want := errUDPTestOutput
	err := respondUDPDatagram(
		t.Context(),
		&net.UDPConn{},
		&net.UDPAddr{},
		[]byte("request"),
		strings.NewReader("response"),
		failingWriter{err: want},
	)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want output failure", err)
	}
}

func TestUDPListenerDiagnosticsReturnOutputFailures(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	if err := writeUDPListeningDetails(failingWriter{err: errUDPTestDiagnostic}, listener); !errors.Is(err, errUDPTestDiagnostic) {
		t.Fatalf("listening diagnostic error = %v, want output failure", err)
	}
	if err := writeUDPReceivedDetails(
		failingWriter{err: errUDPTestDiagnostic},
		listener.LocalAddr(),
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	); !errors.Is(err, errUDPTestDiagnostic) {
		t.Fatalf("received diagnostic error = %v, want output failure", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		closeUDPTest(t, connection)
		t.Fatal(err)
	}
	t.Cleanup(func() { closeUDPTest(t, connection) })
	return connection
}
