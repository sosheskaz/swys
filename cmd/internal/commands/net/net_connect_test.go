package net_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/netconn"
)

var (
	errUnexpectedNetworkRequest = errors.New("unexpected network request")
	errNonTLSConnection         = errors.New("listener returned non-TLS connection")
)

func TestNetCommandAliases(t *testing.T) {
	t.Parallel()
	for _, alias := range []string{"nc", "netcat"} {
		assert.Contains(t, newNetCmd().Aliases, alias)
	}
}

func TestNetConnectTCPRelaysEncodedPayload(t *testing.T) {
	t.Parallel()
	inputPath := filepath.Join(t.TempDir(), "request.b64")
	require.NoError(t, os.WriteFile(inputPath, []byte(base64.StdEncoding.EncodeToString([]byte("request"))), 0o600))
	address, serverResult := startTCPExchangeServer(t, "request", "response", 0)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "--udp=false", "--tls=false", address,
		"--input", inputPath,
		"--input-encoding", "base64",
		"--encoding", "base64",
		"--connect-timeout", "0",
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	decoded, err := base64.StdEncoding.DecodeString(stdout)
	require.NoError(t, err)
	if got := string(decoded); got != "response" {
		t.Fatalf("response = %q, want %q", got, "response")
	}
	if result := <-serverResult; result.err != nil || result.request != "request" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestNetConnectTCPTimeoutOnlyCoversSetup(t *testing.T) {
	t.Parallel()
	inputPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(inputPath, []byte("request"), 0o600))
	address, serverResult := startTCPExchangeServer(t, "request", "delayed", 2*time.Second)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", address,
		"--input", inputPath,
		"--connect-timeout", "1s",
		"--wait", "5s",
		"--verbose",
	)
	require.NoError(t, err)
	assert.Equal(t, "delayed", stdout)
	assert.Contains(t, stderr, "connected tcp")
	if result := <-serverResult; result.err != nil {
		t.Fatal(result.err)
	}
}

func TestNetConnectTCPDrainTimeoutPreservesPartialOutputFile(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "partial-response")
	address, responseStarted, serverDone := startTCPPartialResponseServer(t, "partial response")

	stdout, _, err := executeRootStreamsWithInput(
		t,
		&commandGatedEOFReader{ready: responseStarted},
		"net", "connect", address,
		"--output", outputPath,
		"--close-write=false",
		"-w", "50ms",
	)
	require.ErrorIs(t, err, netconn.ErrDrainTimeout)
	assert.Contains(t, err.Error(), "50ms")
	assert.Empty(t, stdout)
	output, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	require.Equal(t, "partial response", string(output), "preserved response prefix")
	require.NoError(t, <-serverDone)
}

func TestNetConnectTLSMutualAuthenticationWithoutALPN(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, true, []string{"h2", "http/1.1"})
	inputPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(inputPath, []byte("request"), 0o600))

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "-T", "--udp=false", address,
		"--input", inputPath,
		"--ca", identity.caCert,
		"--cert", identity.clientCert,
		"-k", identity.clientKey,
		"--servername", "localhost",
		"--wait", "1s",
		"-v",
	)
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	for _, want := range []string{"connected tls", "version      ", "cipher       ", "alpn         (none)", "server name  localhost"} {
		assert.Contains(t, stderr, want)
	}
	result := <-serverResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.request != "request" || result.alpn != "" || !result.clientVerified {
		t.Fatalf("server result = %+v", result)
	}
}

func TestNetConnectTLSDefaultsToHalfCloseAndDrain(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	requestPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(requestPath, []byte("request"), 0o600))
	address, serverResult := startTLSEOFResponseServer(t, &identity)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	stdout, stderr, err := executeRootCommandStreams(
		t,
		root,
		"net", "connect", "--tls", address,
		"--input", requestPath,
		"--ca", identity.caCert,
		"--servername", "localhost",
	)
	require.NoError(t, err, "default TLS pipe exchange: %v", err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.request != "request" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestNetConnectTLSCustomALPNAndInsecureWarning(t *testing.T) {
	t.Parallel()
	const hostileALPN = "h2\n  server name: attacker.example"
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, false, []string{hostileALPN})
	inputPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(inputPath, []byte("request"), 0o600))

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "--tls", address,
		"--input", inputPath,
		"--servername", "localhost",
		"--alpn", hostileALPN,
		"--insecure",
		"--verbose",
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	assert.Contains(t, stderr, "warning: TLS certificate verification is disabled")
	assert.NotContains(t, stderr, "\n  server name: attacker.example")
	if want := `alpn         h2\n  server name: attacker.example`; !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want escaped ALPN %q", stderr, want)
	}
	if result := <-serverResult; result.err != nil || result.alpn != hostileALPN {
		t.Fatalf("server result = %+v", result)
	}
}

func TestNetConnectTLSCanDisableALPNWithoutVerboseWarning(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, false, []string{"h2", "http/1.1"})
	inputPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(inputPath, []byte("request"), 0o600))

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "--tls", address,
		"--input", inputPath,
		"--alpn=",
		"--insecure",
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.alpn != "" {
		t.Fatalf("server result = %+v, want no negotiated ALPN", result)
	}
}

func TestNetConnectTLSRejectsMismatchedClientIdentityBeforeDial(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	_, _, err := executeRootStreams(
		t,
		"net", "connect", "--tls", "localhost:1",
		"--cert", identity.clientCert,
		"--key", identity.serverKey,
	)
	require.ErrorIs(t, err, errTLSClientKeyMismatch)
}

func TestNetConnectTLSRejectsArtifactOutputCollisionBeforeTruncation(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	want, err := os.ReadFile(identity.clientCert)
	require.NoError(t, err)

	_, _, err = executeRootStreams(
		t,
		"net", "connect", "--tls", "localhost:1",
		"--cert", identity.clientCert,
		"--key", identity.clientKey,
		"--output", identity.clientCert,
	)
	require.ErrorIs(t, err, errCertificatePathCollision)
	got, err := os.ReadFile(identity.clientCert)
	require.NoError(t, err)
	assert.Equal(t, want, got, "client certificate changed after rejected output collision")
}

func TestNetConnectTLSVerificationFailurePreventsPayload(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, false, nil)
	inputPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(inputPath, []byte("must not be sent"), 0o600))

	stdout, _, err := executeRootStreams(
		t,
		"net", "connect", "--tls", address,
		"--input", inputPath,
		"--servername", "localhost",
	)
	require.ErrorContains(t, err, "failed to verify certificate")
	assert.Empty(t, stdout)
	if result := <-serverResult; result.request != "" {
		t.Fatalf("server received %q before verification", result.request)
	}
}

func TestNetConnectTLSFlagValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "cert without key", args: []string{"--cert", "client.crt"}},
		{name: "key without cert", args: []string{"--key", "client.key"}},
		{name: "system CA without custom CA", args: []string{"--system-ca"}},
		{name: "insecure with CA", args: []string{"--insecure", "--ca", "ca.crt"}},
		{name: "insecure with system CA", args: []string{"--insecure", "--system-ca"}},
		{name: "ALPN with whitespace", args: []string{"--alpn", "h2, http/1.1"}},
		{name: "negative wait", args: []string{"--wait", "-1s"}},
		{name: "negative timeout", args: []string{"--connect-timeout", "-1s"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"net", "connect", "--tls", "localhost:443"}, test.args...)
			_, _, err := executeRootStreams(t, args...)
			require.ErrorIs(t, err, errInvalidNetworkFlags)
		})
	}
}

func TestCertConnectVerificationStatusRemainsNonFatal(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	stdout, _, err := executeRootStreams(
		t,
		"cert", "connect", server.Listener.Addr().String(), "--format", "json", "--connect-timeout", "0",
	)
	require.NoError(t, err)
	var report struct {
		Verification struct {
			Error    string `json:"error"`
			Verified bool   `json:"verified"`
		} `json:"verification"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	assert.False(t, report.Verification.Verified)
	assert.NotEmpty(t, report.Verification.Error)
}

func TestCertConnectPositiveTimeoutCoversTLSHandshake(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close listener: %v", closeErr)
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // fixture cleanup
		// Consume ClientHello without answering; EOF follows client cancellation.
		if _, copyErr := io.Copy(io.Discard, conn); copyErr != nil {
			t.Errorf("consume stalled handshake: %v", copyErr)
		}
	}()
	path := filepath.Join(t.TempDir(), "existing.pem")
	require.NoError(t, os.WriteFile(path, []byte("preserve me"), 0o600))
	parent, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	root := newRootCmd()
	root.SetContext(parent)
	_, _, err = executeRootCommandStreams(t, root, "cert", "connect", listener.Addr().String(), "--connect-timeout", "20ms", "-o", path)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, parent.Err(), "the command must use its own setup timeout during preparation")
	require.NoError(t, listener.Close())
	<-done
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve me", string(after))
}

func TestCertConnectConnectionRefusedDoesNotRetry(t *testing.T) {
	t.Parallel()

	reservation, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := reservation.Addr().String()
	require.NoError(t, reservation.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	_, _, err = executeRootCommandStreams(t, root, "cert", "connect", address, "--connect-timeout", "0")
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	if ctx.Err() != nil {
		t.Fatalf("certificate connection refusal exhausted the caller context: %v", ctx.Err())
	}
}

func TestCertConnectPEMReportsVerificationWithoutContaminatingArtifact(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	stdout, stderr, err := executeRootStreams(
		t,
		"cert", "connect", server.Listener.Addr().String(), "--format", "pem",
	)
	require.NoError(t, err)
	if strings.Count(stdout, "-----BEGIN CERTIFICATE-----") != 1 || strings.Contains(stdout, "verification") {
		t.Fatalf("certificate stdout = %q, want one uncontaminated PEM artifact", stdout)
	}
	assert.Contains(t, stderr, "Status  not verified")
}

type exchangeResult struct {
	err            error
	request        string
	alpn           string
	clientVerified bool
}

type commandGatedEOFReader struct {
	ready <-chan struct{}
}

func (reader *commandGatedEOFReader) Read([]byte) (int, error) {
	<-reader.ready
	return 0, io.EOF
}

func startTCPExchangeServer(
	t *testing.T,
	wantRequest string,
	response string,
	responseDelay time.Duration,
) (string, <-chan exchangeResult) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", closeErr)
		}
	})
	result := make(chan exchangeResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- exchangeResult{err: acceptErr}
			return
		}
		defer func() {
			if closeErr := connection.Close(); closeErr != nil {
				t.Errorf("close TCP connection: %v", closeErr)
			}
		}()
		request := make([]byte, len(wantRequest))
		_, readErr := io.ReadFull(connection, request)
		if readErr != nil {
			result <- exchangeResult{err: readErr}
			return
		}
		if string(request) != wantRequest {
			result <- exchangeResult{
				request: string(request),
				err:     fmt.Errorf("%w: got %q, want %q", errUnexpectedNetworkRequest, request, wantRequest),
			}
			return
		}
		time.Sleep(responseDelay)
		_, writeErr := io.WriteString(connection, response)
		result <- exchangeResult{request: string(request), err: writeErr}
	}()
	return listener.Addr().String(), result
}

func startTCPPartialResponseServer(
	t *testing.T,
	prefix string,
) (string, <-chan struct{}, <-chan error) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", closeErr)
		}
	})
	responseStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(responseStarted)
			done <- acceptErr
			return
		}
		_, writeErr := io.WriteString(connection, prefix)
		close(responseStarted)
		_, readErr := io.Copy(io.Discard, connection)
		done <- errors.Join(writeErr, readErr, connection.Close())
	}()
	return listener.Addr().String(), responseStarted, done
}

func executeRootStreamsWithInput(
	t *testing.T,
	input io.Reader,
	args ...string,
) (string, string, error) {
	t.Helper()
	rootCmd := newRootCmd()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCmd.SetIn(input)
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)
	err := commandio.Execute(rootCmd)
	return stdout.String(), stderr.String(), err
}

func startTLSExchangeServer(
	t *testing.T,
	identity *networkTestIdentity,
	requireClient bool,
	nextProtocols []string,
) (string, <-chan exchangeResult) {
	t.Helper()
	serverIdentity, err := tls.LoadX509KeyPair(identity.serverCert, identity.serverKey)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(identity.caCert)
	require.NoError(t, err)
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append client CA")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{serverIdentity},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   nextProtocols,
	}
	if requireClient {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = clientRoots
	}
	baseListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := tls.NewListener(baseListener, config)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TLS listener: %v", closeErr)
		}
	})
	result := make(chan exchangeResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- exchangeResult{err: acceptErr}
			return
		}
		defer func() {
			if closeErr := connection.Close(); closeErr != nil {
				t.Errorf("close TLS connection: %v", closeErr)
			}
		}()
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			result <- exchangeResult{err: errNonTLSConnection}
			return
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if handshakeErr := tlsConnection.HandshakeContext(ctx); handshakeErr != nil {
			result <- exchangeResult{err: handshakeErr}
			return
		}
		state := tlsConnection.ConnectionState()
		request := make([]byte, len("request"))
		_, readErr := io.ReadFull(tlsConnection, request)
		if readErr != nil {
			result <- exchangeResult{err: readErr, alpn: state.NegotiatedProtocol}
			return
		}
		_, writeErr := io.WriteString(tlsConnection, "response")
		result <- exchangeResult{
			err:            writeErr,
			request:        string(request),
			alpn:           state.NegotiatedProtocol,
			clientVerified: len(state.VerifiedChains) > 0,
		}
	}()
	return listener.Addr().String(), result
}

func startTLSEOFResponseServer(
	t *testing.T,
	identity *networkTestIdentity,
) (string, <-chan exchangeResult) {
	t.Helper()
	serverIdentity, err := tls.LoadX509KeyPair(identity.serverCert, identity.serverKey)
	require.NoError(t, err)
	baseListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := tls.NewListener(baseListener, &tls.Config{
		Certificates: []tls.Certificate{serverIdentity},
		MinVersion:   tls.VersionTLS12,
	})
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close TLS EOF listener: %v", closeErr)
		}
	})
	result := make(chan exchangeResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- exchangeResult{err: acceptErr}
			return
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			result <- exchangeResult{err: errors.Join(errNonTLSConnection, connection.Close())}
			return
		}
		request, readErr := io.ReadAll(tlsConnection)
		if readErr != nil {
			result <- exchangeResult{request: string(request), err: errors.Join(readErr, tlsConnection.Close())}
			return
		}
		_, writeErr := io.WriteString(tlsConnection, "response")
		result <- exchangeResult{
			request: string(request),
			err:     errors.Join(writeErr, tlsConnection.Close()),
		}
	}()
	return listener.Addr().String(), result
}

func TestNetConnectTLSCredentialFailurePreservesOutputAndInput(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	for _, test := range []struct {
		want  error
		name  string
		flags []string
	}{
		{want: os.ErrNotExist, name: "missing CA", flags: []string{"--ca", filepath.Join(t.TempDir(), "missing.pem")}},
		{want: errTLSClientKeyMismatch, name: "mismatched identity", flags: []string{"--cert", identity.clientCert, "--key", identity.serverKey}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "response")
			require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
			payload := strings.NewReader("payload")
			root := newRootCmd()
			root.SetIn(payload)
			args := append([]string{"net", "connect", "--tls", "localhost:1", "--output", output}, test.flags...)
			_, _, err := executeRootCommandStreams(t, root, args...)
			require.ErrorIs(t, err, test.want)
			remaining, err := os.ReadFile(output)
			require.NoError(t, err)
			assert.Equal(t, "sentinel", string(remaining))
			assert.Equal(t, len("payload"), payload.Len())
		})
	}
}

func TestNetConnectTLSReloadsCredentialsOnRootReuse(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	ca, err := os.ReadFile(identity.caCert)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(caPath, ca, 0o600))
	address, serverResult := startTLSExchangeServer(t, &identity, false, nil)
	root := newRootCmd()
	originalContext := t.Context()
	root.SetContext(originalContext)
	leaf, _, err := root.Find([]string{"net", "connect"})
	require.NoError(t, err)
	leaf.SetContext(originalContext)
	root.SetIn(strings.NewReader("request"))
	output := filepath.Join(t.TempDir(), "response")
	args := []string{"net", "connect", "--tls", address, "--ca", caPath, "--servername", "localhost", "--wait", "1s", "--output", output}
	_, _, err = executeRootCommandStreams(t, root, args...)
	require.NoError(t, err)
	result := <-serverResult
	require.NoError(t, result.err)
	assert.Equal(t, "request", result.request)
	assert.Same(t, originalContext, leaf.Context())
	require.NoError(t, os.WriteFile(caPath, nil, 0o600))
	require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
	payload := strings.NewReader("payload")
	root.SetIn(payload)
	_, _, err = executeRootCommandStreams(t, root, args...)
	require.ErrorIs(t, err, certinput.ErrNoCertificates)
	remaining, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "sentinel", string(remaining))
	assert.Equal(t, len("payload"), payload.Len())
	assert.Same(t, originalContext, leaf.Context())
}
