package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var (
	errUnexpectedNetworkRequest = errors.New("unexpected network request")
	errNonTLSConnection         = errors.New("listener returned non-TLS connection")
)

func TestNetCommandAliases(t *testing.T) {
	t.Parallel()
	for _, alias := range []string{"nc", "netcat"} {
		if !slices.Contains(newNetCmd().Aliases, alias) {
			t.Fatalf("net aliases = %v, want %q", newNetCmd().Aliases, alias)
		}
	}
}

func TestNetConnectTCPRelaysEncodedPayload(t *testing.T) {
	t.Parallel()
	inputPath := filepath.Join(t.TempDir(), "request.b64")
	if err := os.WriteFile(inputPath, []byte(base64.StdEncoding.EncodeToString([]byte("request"))), 0o600); err != nil {
		t.Fatal(err)
	}
	address, serverResult := startTCPExchangeServer(t, "request", "response", 0)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tcp", address,
		"--input", inputPath,
		"--input-encoding", "base64",
		"--encoding", "base64",
		"--timeout", "0",
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want quiet success", stderr)
	}
	decoded, err := base64.StdEncoding.DecodeString(stdout)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(inputPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	address, serverResult := startTCPExchangeServer(t, "request", "delayed", 2*time.Second)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tcp", address,
		"--input", inputPath,
		"--timeout", "1s",
		"--wait", "5s",
		"--verbose",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "delayed" {
		t.Fatalf("response = %q, want delayed", stdout)
	}
	if !strings.Contains(stderr, "connected tcp") {
		t.Fatalf("stderr = %q, want TCP connection details", stderr)
	}
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
		"net", "connect", "tcp", address,
		"--output", outputPath,
		"--close-write=false",
		"--wait", "50ms",
	)
	if !errors.Is(err, netconn.ErrDrainTimeout) {
		t.Fatalf("error = %v, want drain timeout", err)
	}
	if !strings.Contains(err.Error(), "50ms") {
		t.Fatalf("error = %q, want elapsed wait", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want response redirected to file", stdout)
	}
	output, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(output) != "partial response" {
		t.Fatalf("partial output = %q, want preserved response prefix", output)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestNetConnectTLSMutualAuthenticationWithoutALPN(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, true, []string{"h2", "http/1.1"})
	inputPath := filepath.Join(t.TempDir(), "request")
	if err := os.WriteFile(inputPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tls", address,
		"--input", inputPath,
		"--ca", identity.caCert,
		"--cert", identity.clientCert,
		"--key", identity.clientKey,
		"--servername", "localhost",
		"--wait", "1s",
		"--verbose",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want response", stdout)
	}
	for _, want := range []string{"connected tls", "version:", "cipher:", "alpn: (none)", "server name: localhost"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want %q", stderr, want)
		}
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
	if err := os.WriteFile(requestPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	address, serverResult := startTLSEOFResponseServer(t, &identity)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	stdout, stderr, err := executeRootCommandStreams(
		t,
		root,
		"net", "connect", "tls", address,
		"--input", requestPath,
		"--ca", identity.caCert,
		"--servername", "localhost",
	)
	if err != nil {
		t.Fatalf("default TLS pipe exchange: %v", err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want response", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want quiet success", stderr)
	}
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
	if err := os.WriteFile(inputPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tls", address,
		"--input", inputPath,
		"--servername", "localhost",
		"--alpn", hostileALPN,
		"--insecure",
		"--verbose",
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want response", stdout)
	}
	if !strings.Contains(stderr, "warning: TLS certificate verification is disabled") {
		t.Fatalf("stderr = %q, want insecure warning", stderr)
	}
	if strings.Contains(stderr, "\n  server name: attacker.example") {
		t.Fatalf("stderr contains forged ALPN diagnostic line: %q", stderr)
	}
	if want := `alpn: h2\n  server name: attacker.example`; !strings.Contains(stderr, want) {
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
	if err := os.WriteFile(inputPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tls", address,
		"--input", inputPath,
		"--alpn=",
		"--insecure",
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want response", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want quiet success without --verbose", stderr)
	}
	if result := <-serverResult; result.err != nil || result.alpn != "" {
		t.Fatalf("server result = %+v, want no negotiated ALPN", result)
	}
}

func TestNetConnectTLSRejectsMismatchedClientIdentityBeforeDial(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	_, _, err := executeRootStreams(
		t,
		"net", "connect", "tls", "localhost:1",
		"--cert", identity.clientCert,
		"--key", identity.serverKey,
	)
	if !errors.Is(err, errTLSClientKeyMismatch) {
		t.Fatalf("error = %v, want errTLSClientKeyMismatch", err)
	}
}

func TestNetConnectTLSRejectsArtifactOutputCollisionBeforeTruncation(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	want, err := os.ReadFile(identity.clientCert)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = executeRootStreams(
		t,
		"net", "connect", "tls", "localhost:1",
		"--cert", identity.clientCert,
		"--key", identity.clientKey,
		"--output", identity.clientCert,
	)
	if !errors.Is(err, errCertificatePathCollision) {
		t.Fatalf("error = %v, want errCertificatePathCollision", err)
	}
	got, err := os.ReadFile(identity.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("client certificate changed after rejected output collision")
	}
}

func TestNetConnectTLSVerificationFailurePreventsPayload(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	address, serverResult := startTLSExchangeServer(t, &identity, false, nil)
	inputPath := filepath.Join(t.TempDir(), "request")
	if err := os.WriteFile(inputPath, []byte("must not be sent"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := executeRootStreams(
		t,
		"net", "connect", "tls", address,
		"--input", inputPath,
		"--servername", "localhost",
	)
	if err == nil || !strings.Contains(err.Error(), "failed to verify certificate") {
		t.Fatalf("error = %v, want certificate verification failure", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no payload", stdout)
	}
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
		{name: "negative timeout", args: []string{"--timeout", "-1s"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"net", "connect", "tls", "localhost:443"}, test.args...)
			if _, _, err := executeRootStreams(t, args...); !errors.Is(err, errInvalidNetworkFlags) {
				t.Fatalf("error = %v, want errInvalidNetworkFlags", err)
			}
		})
	}
}

func TestCertConnectVerificationStatusRemainsNonFatal(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	stdout, _, err := executeRootStreams(
		t,
		"cert", "connect", server.Listener.Addr().String(), "--format", "json", "--timeout", "0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `"verified": false`) || !strings.Contains(stdout, `"verify_error"`) {
		t.Fatalf("certificate JSON = %s, want non-fatal verification status", stdout)
	}
}

func TestCertConnectPositiveTimeoutCoversTLSHandshake(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close stalled TLS listener: %v", closeErr)
		}
	})
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	_, _, err = executeRootStreams(
		t,
		"cert", "connect", listener.Addr().String(), "--timeout", "25ms",
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}

	select {
	case connection := <-accepted:
		if closeErr := connection.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake connection was not accepted")
	}
}

func TestCertConnectConnectionRefusedDoesNotRetry(t *testing.T) {
	t.Parallel()

	reservation, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	_, _, err = executeRootCommandStreams(t, root, "cert", "connect", address, "--timeout", "0")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want connection refused", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(stdout, "-----BEGIN CERTIFICATE-----") != 1 || strings.Contains(stdout, "verification") {
		t.Fatalf("certificate stdout = %q, want one uncontaminated PEM artifact", stdout)
	}
	if !strings.Contains(stderr, "certificate verification: not verified:") {
		t.Fatalf("stderr = %q, want non-fatal verification status", stderr)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	command, runErr := rootCmd.ExecuteC()
	err := errors.Join(runErr, closeCommandIO(command))
	return stdout.String(), stderr.String(), err
}

type networkTestIdentity struct {
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func createNetworkTestIdentity(t *testing.T) networkTestIdentity {
	t.Helper()
	directory := t.TempDir()
	identity := networkTestIdentity{
		caCert:     filepath.Join(directory, "ca.crt"),
		serverCert: filepath.Join(directory, "server.crt"),
		serverKey:  filepath.Join(directory, "server.key"),
		clientCert: filepath.Join(directory, "client.crt"),
		clientKey:  filepath.Join(directory, "client.key"),
	}
	caKey := filepath.Join(directory, "ca.key")
	generateTestKey(t, "ed25519", caKey)
	generateTestKey(t, "ed25519", identity.serverKey)
	generateTestKey(t, "ed25519", identity.clientKey)
	commands := [][]string{
		{"cert", "create", "--ca", "--subject", "CN=test-ca", "--key", caKey, "--output", identity.caCert},
		{
			"cert", "create", "--dns", "localhost", "--server-only", "--key", identity.serverKey,
			"--issuer-cert", identity.caCert, "--issuer-key", caKey, "--output", identity.serverCert,
		},
		{
			"cert", "create", "--subject", "CN=client", "--client-only", "--key", identity.clientKey,
			"--issuer-cert", identity.caCert, "--issuer-key", caKey, "--output", identity.clientCert,
		},
	}
	for _, args := range commands {
		if _, _, err := executeRootStreams(t, args...); err != nil {
			t.Fatalf("execute %v: %v", args, err)
		}
	}
	return identity
}

func startTLSExchangeServer(
	t *testing.T,
	identity *networkTestIdentity,
	requireClient bool,
	nextProtocols []string,
) (string, <-chan exchangeResult) {
	t.Helper()
	serverIdentity, err := tls.LoadX509KeyPair(identity.serverCert, identity.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(identity.caCert)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	baseListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
