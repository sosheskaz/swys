package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var errListenDiagnosticOutput = errors.New("diagnostic output failed")

func TestNetListenTCPDefaultsToUnlimitedAcceptWait(t *testing.T) {
	t.Parallel()
	if got := newNetListenTCPCmd().Flags().Lookup("timeout").DefValue; got != "0s" {
		t.Fatalf("listen timeout default = %q, want 0s", got)
	}
	if got := newNetConnectTCPCmd().Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Fatalf("connect timeout default = %q, want unchanged 10s", got)
	}
	if got := newNetListenTLSCmd().Flags().Lookup("timeout").DefValue; got != "0s" {
		t.Fatalf("TLS listen timeout default = %q, want 0s", got)
	}
	if got := newNetConnectTLSCmd().Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Fatalf("TLS connect timeout default = %q, want unchanged 10s", got)
	}
}

func TestNetListenTCPPositiveAcceptTimeout(t *testing.T) {
	t.Parallel()
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

func TestNetListenTCPRejectsMissingPort(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"localhost:", ":", "localhost", "http", "65536"} {
		_, _, err := executeRootStreams(t, "net", "listen", "tcp", address)
		if !errors.Is(err, errInvalidHostPort) {
			t.Fatalf("address %q error = %v, want errInvalidHostPort", address, err)
		}
	}
}

func TestNetListenTCPAcceptsColonPortCompatibility(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(
		t,
		"net", "listen", "tcp", ":0",
		"--timeout", "30ms",
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded after accepting :port", err)
	}
}

func TestNetListenHelpDocumentsOptionalHost(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{"tcp", "tls"} {
		stdout, _, err := executeRootStreams(t, "net", "listen", protocol, "--help")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, protocol+" [host:]port") {
			t.Fatalf("%s help = %q, want optional host usage", protocol, stdout)
		}
	}
}

func TestNetConnectStillRejectsMissingHost(t *testing.T) {
	t.Parallel()
	for _, address := range []string{":8080", "8080"} {
		_, _, err := executeRootStreams(t, "net", "connect", "tcp", address)
		if !errors.Is(err, errInvalidHostPort) {
			t.Fatalf("address %q error = %v, want errInvalidHostPort", address, err)
		}
	}
}

func TestNetListenTCPBindFailure(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
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
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("request"),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--timeout", "50ms",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
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
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("request"),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--close-write",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
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
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--verbose",
		"--wait", "50ms",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
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
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "tcp", "127.0.0.1:0",
		"--verbose",
		"--wait", "0",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tcp ")
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

func TestNetListenTLSVerifiedServerWithoutClientAuthentication(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	run := startExampleListenCommand(
		t,
		strings.NewReader("server payload"),
		"net", "listen", "tls", "127.0.0.1:0",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--timeout", "50ms",
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTLS(t, address, tlsClientConfig(t, &identity, nil, nil))
	if _, err := io.WriteString(connection, "client payload"); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("server payload"))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	closeListenTestTCP(t, connection)
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "client payload" {
		t.Fatalf("listener output = %q, want client payload", got)
	}
	if got := string(received); got != "server payload" {
		t.Fatalf("client received %q, want server payload", got)
	}
	stderrText := <-stderr
	for _, want := range []string{
		"accepted tls ",
		"version: TLS",
		"cipher: TLS_",
		"alpn: (none)",
		"sni: localhost",
		"peer certificates: 0",
		"client chain verified: no",
	} {
		if !strings.Contains(stderrText, want) {
			t.Fatalf("stderr = %q, want %q", stderrText, want)
		}
	}
}

func TestNetListenTLSVerboseEscapesSNI(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	run := startExampleListenCommand(
		t,
		strings.NewReader(""),
		"net", "listen", "tls", "127.0.0.1:0",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--verbose",
		"--wait", "1s",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	stderr := drainExampleStderr(run.stderr)
	config := tlsClientConfig(t, &identity, nil, nil)
	config.ServerName = "peer.example\nFORGED-DIAGNOSTIC\x1b[2J"
	// The hostile SNI intentionally cannot match the test server certificate.
	config.InsecureSkipVerify = true
	connection := dialListenTestTLS(t, address, config)
	closeListenTestTCP(t, connection)
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	stderrText := <-stderr
	if strings.Contains(stderrText, "\nFORGED-DIAGNOSTIC") || strings.Contains(stderrText, "\x1b") {
		t.Fatalf("stderr contains peer-controlled terminal controls: %q", stderrText)
	}
	if want := `sni: peer.example\nFORGED-DIAGNOSTIC\x1b[2J`; !strings.Contains(stderrText, want) {
		t.Fatalf("stderr = %q, want escaped SNI %q", stderrText, want)
	}
}

func TestNetListenTLSRequiresAndValidatesServerIdentityBeforeBind(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	_, _, err := executeRootStreams(t, "net", "listen", "tls", "127.0.0.1:0")
	if err == nil || !strings.Contains(err.Error(), "required flag") {
		t.Fatalf("missing identity error = %v, want required flags", err)
	}
	_, _, err = executeRootStreams(
		t,
		"net", "listen", "tls", "127.0.0.1:0",
		"--cert", identity.serverCert,
		"--key", identity.clientKey,
	)
	if !errors.Is(err, errTLSServerKeyMismatch) {
		t.Fatalf("mismatched identity error = %v, want errTLSServerKeyMismatch", err)
	}
}

func TestNetListenTLSRejectsUnusableServerIdentityBeforeBind(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	now := time.Now()
	expiredCert, expiredKey := writeListenTestSelfSignedIdentity(
		t,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	futureCert, futureKey := writeListenTestSelfSignedIdentity(
		t,
		now.Add(time.Hour),
		now.Add(2*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	brokenCert, brokenKey := writeListenTestBrokenChain(t)
	outOfOrderCert, outOfOrderKey := writeListenTestOutOfOrderChain(t)

	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close occupied listener: %v", err)
		}
	})
	tests := []struct {
		name string
		cert string
		key  string
	}{
		{name: "expired", cert: expiredCert, key: expiredKey},
		{name: "not yet valid", cert: futureCert, key: futureKey},
		{name: "client-only usage", cert: identity.clientCert, key: identity.clientKey},
		{name: "unrelated issuer", cert: brokenCert, key: brokenKey},
		{name: "out-of-order extra certificate", cert: outOfOrderCert, key: outOfOrderKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := executeRootStreams(
				t,
				"net", "listen", "tls", occupied.Addr().String(),
				"--cert", test.cert,
				"--key", test.key,
			)
			if err == nil || !strings.Contains(err.Error(), "validate --cert server certificate chain") {
				t.Fatalf("error = %v, want server identity validation failure", err)
			}
			if strings.Contains(err.Error(), "listen on TCP endpoint") {
				t.Fatalf("error = %v, want identity validation before bind", err)
			}
		})
	}
}

func TestValidateTLSServerIdentityAcceptsPresentedOrder(t *testing.T) {
	t.Parallel()
	certificates, privateKey := newListenTestIntermediateChain(t)
	identity := tls.Certificate{Certificate: certificates, PrivateKey: privateKey}
	if err := validateTLSServerIdentity(&identity); err != nil {
		t.Fatal(err)
	}
}

func TestNetListenTLSRejectsMalformedCABeforeBind(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	caPath := filepath.Join(t.TempDir(), "malformed-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close occupied listener: %v", err)
		}
	})
	_, _, err = executeRootStreams(
		t,
		"net", "listen", "tls", occupied.Addr().String(),
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--ca", caPath,
	)
	if !errors.Is(err, errTrailingCertificateData) {
		t.Fatalf("error = %v, want malformed CA before bind failure", err)
	}
}

func TestNetListenTLSRejectsMissingAndUntrustedClientsWithoutPayload(t *testing.T) {
	t.Parallel()
	serverIdentity := createNetworkTestIdentity(t)
	untrustedIdentity := createNetworkTestIdentity(t)
	untrustedClient, err := tls.LoadX509KeyPair(untrustedIdentity.clientCert, untrustedIdentity.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		identity *tls.Certificate
		name     string
	}{
		{name: "missing client certificate"},
		{name: "untrusted client certificate", identity: &untrustedClient},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			run := startExampleListenCommand(
				t,
				strings.NewReader("must not be sent"),
				"net", "listen", "tls", "127.0.0.1:0",
				"--cert", serverIdentity.serverCert,
				"--key", serverIdentity.serverKey,
				"--ca", serverIdentity.caCert,
				"--timeout", "1s",
				"--verbose",
			)
			address := readExampleListeningAddress(t, run.stderr, "listening tls ")
			stderr := drainExampleStderr(run.stderr)
			config := tlsClientConfig(t, &serverIdentity, test.identity, nil)
			connection, dialErr := (&tls.Dialer{
				NetDialer: &net.Dialer{Timeout: time.Second},
				Config:    config,
			}).DialContext(t.Context(), "tcp", address)
			if dialErr == nil {
				if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1)
				n, readErr := connection.Read(buffer)
				closeListenTestTCP(t, connection)
				if n != 0 || readErr == nil {
					t.Fatalf("unauthenticated client received %q with error %v", buffer[:n], readErr)
				}
			}
			if err := <-run.done; err == nil || !strings.Contains(err.Error(), "handshake with accepted TLS connection") {
				t.Fatalf("listener error = %v, want failed authenticated handshake", err)
			}
			if got := run.stdout.String(); got != "" {
				t.Fatalf("listener output = %q, want no unauthenticated payload", got)
			}
			<-stderr
		})
	}
}

func TestNetListenTLSHandshakeTimeoutClosesConnection(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	run := startExampleListenCommand(
		t,
		strings.NewReader("must not be sent"),
		"net", "listen", "tls", "127.0.0.1:0",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
		"--timeout", "50ms",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening tls ")
	stderr := drainExampleStderr(run.stderr)
	connection := dialListenTestTCP(t, address)
	if err := <-run.done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want TLS handshake deadline", err)
	}
	if got := run.stdout.String(); got != "" {
		t.Fatalf("listener output = %q, want no pre-handshake payload", got)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if n, err := connection.Read(buffer); n != 0 || err == nil {
		t.Fatalf("stalled client read = (%d, %v), want closed connection", n, err)
	}
	closeListenTestTCP(t, connection)
	<-stderr
}

func TestNetListenTLSFlagValidation(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	base := []string{
		"net", "listen", "tls", "127.0.0.1:0",
		"--cert", identity.serverCert,
		"--key", identity.serverKey,
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "system CA without bundle", args: []string{"--system-ca"}},
		{name: "ALPN with whitespace", args: []string{"--alpn", "h2, http/1.1"}},
		{name: "negative timeout", args: []string{"--timeout", "-1s"}},
		{name: "negative wait", args: []string{"--wait", "-1s"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append(slices.Clone(base), test.args...)
			if _, _, err := executeRootStreams(t, args...); !errors.Is(err, errInvalidNetworkFlags) {
				t.Fatalf("error = %v, want errInvalidNetworkFlags", err)
			}
		})
	}
	for _, flag := range []string{"--insecure", "--servername"} {
		args := append(slices.Clone(base), flag)
		if _, _, err := executeRootStreams(t, args...); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Fatalf("%s error = %v, want unsupported flag", flag, err)
		}
	}
}

func tlsClientConfig(
	t *testing.T,
	identity *networkTestIdentity,
	clientIdentity *tls.Certificate,
	nextProtocols []string,
) *tls.Config {
	t.Helper()
	caPEM, err := os.ReadFile(identity.caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append listener test CA")
	}
	config := &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: nextProtocols}
	if clientIdentity != nil {
		config.Certificates = []tls.Certificate{*clientIdentity}
	}
	return config
}

func dialListenTestTLS(t *testing.T, address string, config *tls.Config) *tls.Conn {
	t.Helper()
	connection, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: time.Second},
		Config:    config,
	}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		closeListenTestTCP(t, connection)
		t.Fatalf("connection type = %T, want *tls.Conn", connection)
	}
	return tlsConnection
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

func writeListenTestSelfSignedIdentity(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	extKeyUsage []x509.ExtKeyUsage,
) (string, string) {
	t.Helper()
	identity := newTLSCertificateChain(t)
	key, ok := identity.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", identity.PrivateKey)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "listener-test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return writeListenTestIdentityFiles(t, [][]byte{der}, key)
}

func writeListenTestBrokenChain(t *testing.T) (string, string) {
	t.Helper()
	identity := newTLSCertificateChain(t)
	unrelated := newTLSCertificateChain(t)
	return writeListenTestIdentityFiles(
		t,
		[][]byte{identity.Certificate[0], unrelated.Certificate[1]},
		identity.PrivateKey,
	)
}

func writeListenTestOutOfOrderChain(t *testing.T) (string, string) {
	t.Helper()
	certificates, leafKey := newListenTestIntermediateChain(t)
	unrelated := newTLSCertificateChain(t)
	return writeListenTestIdentityFiles(
		t,
		[][]byte{certificates[0], unrelated.Certificate[1], certificates[1], certificates[2]},
		leafKey,
	)
}

func newListenTestIntermediateChain(t *testing.T) ([][]byte, ed25519.PrivateKey) {
	t.Helper()
	now := time.Now()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ordered root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediatePublic, intermediateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ordered intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		root,
		intermediatePublic,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPublic, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ordered leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		intermediate,
		leafPublic,
		intermediateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leafDER, intermediateDER, rootDER}, leafKey
}

func writeListenTestIdentityFiles(t *testing.T, certificates [][]byte, privateKey any) (string, string) {
	t.Helper()
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	var certPEM []byte
	for _, certificate := range certificates {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
