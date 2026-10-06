package net_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

const exampleStreamPayloadSize = 4 << 20

var errUnexpectedListenerInputRead = errors.New("listener read input in receive-only mode")

func TestExampleNetListenTCPDrainsFileResponseAfterClientEOF(t *testing.T) {
	t.Parallel()
	response := exampleStreamPayload("TCP file response\n")
	inputPath := filepath.Join(t.TempDir(), "response.bin")
	require.NoError(t, os.WriteFile(inputPath, response, 0o600))
	run := startExampleListenCommand(
		t,
		&unexpectedListenerInputReader{},
		"net", "listen", "127.0.0.1:0",
		"--input", inputPath,
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
	remainingStderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	received := exchangeExampleHalfClosedRequest(t, connection, "request")

	require.NoError(t, <-run.done)
	assertExamplePayload(t, received, response)
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want request", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted endpoint summary", stderr)
	}
}

func TestExampleNetListenTCPDrainsPipeResponseAfterClientEOF(t *testing.T) {
	t.Parallel()
	response := exampleStreamPayload("TCP pipe response\n")
	responseReader, responseWriter := io.Pipe()
	t.Cleanup(func() {
		_ = responseReader.Close() //nolint:errcheck // best-effort fixture cleanup
		_ = responseWriter.Close() //nolint:errcheck // best-effort fixture cleanup
	})
	run := startExampleListenCommand(
		t,
		responseReader,
		"net", "listen", "127.0.0.1:0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
	remainingStderr := drainExampleStderr(run.stderr)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := responseWriter.Write(response)
		writeDone <- errors.Join(writeErr, responseWriter.Close())
	}()
	connection := dialListenTestTCP(t, address)
	received := exchangeExampleHalfClosedRequest(t, connection, "request")

	require.NoError(t, <-run.done)
	assertExamplePayload(t, received, response)
	require.NoError(t, <-writeDone)
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want request", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted endpoint summary", stderr)
	}
}

func TestExampleNetListenTLSDrainsFileResponseAfterClientEOF(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	response := exampleStreamPayload("TLS file response\n")
	inputPath := filepath.Join(t.TempDir(), "response.bin")
	require.NoError(t, os.WriteFile(inputPath, response, 0o600))
	run := startExampleListenCommand(
		t,
		&unexpectedListenerInputReader{},
		"net", "listen", "--tls", "127.0.0.1:0",
		"--input", inputPath,
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	remainingStderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTLS(t, address, tlsClientConfig(t, &identity, nil, nil))
	received := exchangeExampleHalfClosedRequest(t, connection, "request")

	require.NoError(t, <-run.done)
	assertExamplePayload(t, received, response)
	if got := run.stdout.String(); got != "request" {
		t.Fatalf("listener output = %q, want request", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tls ") {
		t.Fatalf("stderr = %q, want accepted TLS summary", stderr)
	}
}

func TestExampleNetListenTCPReceiveOnlyDrainsRequestWithoutReadingInput(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"-r", "--recv-only"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			request := exampleStreamPayload("receive-only request\n")
			input := &unexpectedListenerInputReader{}
			run := startExampleListenCommand(
				t,
				input,
				"net", "listen", "127.0.0.1:0",
				flag,
				"--verbose",
			)
			address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
			remainingStderr := drainExampleStderr(run.stderr)
			connection := dialListenTestTCP(t, address)
			exchangeExampleReceiveOnlyRequest(t, connection, request)

			if err := <-run.done; err != nil {
				t.Fatal(err)
			}
			if got := input.reads.Load(); got != 0 {
				t.Fatalf("listener input reads = %d, want 0", got)
			}
			assertExamplePayload(t, run.stdout.Bytes(), request)
			if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tcp ") {
				t.Fatalf("stderr = %q, want accepted endpoint summary", stderr)
			}
		})
	}
}

func TestExampleNetListenTLSReceiveOnlyDrainsRequestWithoutReadingInput(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	request := exampleStreamPayload("TLS receive-only request\n")
	input := &unexpectedListenerInputReader{}
	run := startExampleListenCommand(
		t,
		input,
		"net", "listen", "--tls", "127.0.0.1:0",
		"--recv-only",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	remainingStderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTLS(t, address, tlsClientConfig(t, &identity, nil, nil))
	exchangeExampleReceiveOnlyRequest(t, connection, request)

	require.NoError(t, <-run.done)
	if got := input.reads.Load(); got != 0 {
		t.Fatalf("listener input reads = %d, want 0", got)
	}
	assertExamplePayload(t, run.stdout.Bytes(), request)
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tls ") {
		t.Fatalf("stderr = %q, want accepted TLS summary", stderr)
	}
}

func TestExampleNetListenTCPBidirectionalRelay(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("hello from listener"),
		"net", "listen", "0",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
	remainingStderr := drainExampleStderr(run.stderr)
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)

	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(
		t.Context(),
		"tcp",
		net.JoinHostPort("127.0.0.1", port),
	)
	require.NoError(t, err)
	if _, err := io.WriteString(connection, "hello from client"); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("hello from listener"))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, connection.Close())
	if got := string(received); got != "hello from listener" {
		t.Fatalf("client received %q, want listener input", got)
	}

	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "hello from client" {
		t.Fatalf("listener output = %q, want client payload", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "accepted tcp ") {
		t.Fatalf("stderr = %q, want accepted endpoint summary", stderr)
	}
}

func TestExampleNetListenTLSMutualAuthentication(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	run := startExampleListenCommand(
		t,
		strings.NewReader("hello from TLS listener"),
		"net", "listen", "--tls", "0",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--ca", identity.caCert,
		"--system-ca",
		"--alpn", "swys-example",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	remainingStderr := drainExampleStderr(run.stderr)
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)

	clientIdentity, err := tls.LoadX509KeyPair(identity.clientCert, identity.clientKey)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(identity.caCert)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append example CA")
	}
	connection, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: time.Second},
		Config: &tls.Config{
			Certificates: []tls.Certificate{clientIdentity},
			RootCAs:      roots,
			ServerName:   "localhost",
			NextProtos:   []string{"swys-example"},
		},
	}).DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	if _, err := io.WriteString(connection, "hello from TLS client"); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("hello from TLS listener"))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		t.Fatalf("connection type = %T, want *tls.Conn", connection)
	}
	if got := tlsConnection.ConnectionState().NegotiatedProtocol; got != "swys-example" {
		t.Fatalf("negotiated ALPN = %q, want swys-example", got)
	}
	require.NoError(t, connection.Close())
	if got := string(received); got != "hello from TLS listener" {
		t.Fatalf("client received %q, want TLS listener input", got)
	}

	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "hello from TLS client" {
		t.Fatalf("listener output = %q, want TLS client payload", got)
	}
	stderr := <-remainingStderr
	for _, want := range []string{
		"accepted tls ",
		"alpn: swys-example",
		"sni: localhost",
		"peer certificates: 1",
		"client chain verified: yes",
	} {
		assert.Contains(t, stderr, want)
	}
}

type exampleListenRun struct {
	stderr *bufio.Reader
	stdout *bytes.Buffer
	done   <-chan error
	cancel context.CancelFunc
}

func startExampleListenCommand(
	t *testing.T,
	input io.Reader,
	args ...string,
) exampleListenRun {
	t.Helper()
	rootCmd := newRootCmd()
	ctx, cancel := context.WithCancel(t.Context())
	rootCmd.SetContext(ctx)
	rootCmd.SetArgs(args)
	rootCmd.SetIn(input)

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	stderrReader, stderrWriter := io.Pipe()
	rootCmd.SetErr(stderrWriter)

	done := make(chan error, 1)
	go func() {
		runErr := commandio.Execute(rootCmd)
		runErr = errors.Join(runErr, stderrWriter.Close())
		done <- runErr
	}()
	t.Cleanup(cancel)

	return exampleListenRun{stderr: bufio.NewReader(stderrReader), stdout: &stdout, done: done, cancel: cancel}
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

func readExampleListeningAddress(t *testing.T, reader *bufio.Reader, prefix string) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	require.NoError(t, err, "read listening diagnostic: %v", err)
	line = strings.TrimSpace(line)
	address, found := strings.CutPrefix(line, prefix)
	if !found {
		t.Fatalf("listening diagnostic = %q, want prefix %q", line, prefix)
	}
	return address
}

type exampleHalfCloseConnection interface {
	net.Conn
	CloseWrite() error
}

type unexpectedListenerInputReader struct {
	reads atomic.Int64
}

func (reader *unexpectedListenerInputReader) Read([]byte) (int, error) {
	reader.reads.Add(1)
	return 0, errUnexpectedListenerInputRead
}

func exampleStreamPayload(pattern string) []byte {
	repetitions := (exampleStreamPayloadSize + len(pattern) - 1) / len(pattern)
	return bytes.Repeat([]byte(pattern), repetitions)[:exampleStreamPayloadSize]
}

func exchangeExampleHalfClosedRequest(
	t *testing.T,
	connection exampleHalfCloseConnection,
	request string,
) []byte {
	t.Helper()
	t.Cleanup(func() { _ = connection.Close() }) //nolint:errcheck // best-effort fixture cleanup
	require.NoError(t, connection.SetDeadline(time.Now().Add(10*time.Second)))
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, connection.CloseWrite())
	response, err := io.ReadAll(connection)
	require.NoError(t, err)
	require.NoError(t, connection.Close())
	return response
}

func assertExamplePayload(t *testing.T, got, want []byte) {
	t.Helper()
	if len(got) != len(want) || sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatalf(
			"payload = %d bytes sha256:%x, want %d bytes sha256:%x",
			len(got),
			sha256.Sum256(got),
			len(want),
			sha256.Sum256(want),
		)
	}
}

func exchangeExampleReceiveOnlyRequest(
	t *testing.T,
	connection exampleHalfCloseConnection,
	request []byte,
) {
	t.Helper()
	t.Cleanup(func() { _ = connection.Close() }) //nolint:errcheck // best-effort fixture cleanup
	require.NoError(t, connection.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	buffer := make([]byte, 1)
	if n, err := connection.Read(buffer); n != 0 || !isExampleTimeout(err) {
		t.Fatalf("read before request EOF = (%d, %v), want open idle sending half", n, err)
	}
	require.NoError(t, connection.SetDeadline(time.Now().Add(10*time.Second)))
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, connection.CloseWrite())
	if response, err := io.ReadAll(connection); err != nil || len(response) != 0 {
		t.Fatalf("receive-only response = %d bytes, error %v; want empty success", len(response), err)
	}
	require.NoError(t, connection.Close())
}

func isExampleTimeout(err error) bool {
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}
