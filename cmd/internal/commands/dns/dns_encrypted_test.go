package dns_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
	"github.com/sosheskaz/swys/internal/dnsquery"
)

var (
	errNonTLSConnection         = errors.New("listener returned non-TLS connection")
	errUnexpectedDoHMethod      = errors.New("unexpected DoH method")
	errUnexpectedDoHContentType = errors.New("unexpected DoH content type")
	errDoHTestRequestTooLarge   = errors.New("DoH test request is too large")
	errDNSFixtureTargetTooSmall = errors.New("DNS fixture target is too small")
	errDNSFixtureLengthMismatch = errors.New("DNS fixture length mismatch")
)

func TestEncryptedDNSRemovesTransportFlagAndRedirectOptIn(t *testing.T) {
	t.Parallel()

	root := newRootCmd()
	command, _, err := root.Find([]string{"dns"})
	require.NoError(t, err)
	for _, name := range []string{"transport", "follow-redirects", "redirect"} {
		assert.Nil(t, command.Flags().Lookup(name), "dns --%s remains available", name)
	}
	_, ok := command.GetFlagCompletionFunc("transport")
	assert.False(t, ok, "dns --transport completion remains registered")
	stdout, stderr, err := executeRootStreams(t, "dns", "--help")
	require.NoError(t, err)
	assert.NotContains(t, stdout+stderr, "--transport", "DNS help")
}

func TestEncryptedDNSEndpointValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "missing at prefix", endpoint: "https://resolver.example/dns-query"},
		{name: "userinfo", endpoint: "@https://user@resolver.example/dns-query"},
		{name: "fragment", endpoint: "@https://resolver.example/dns-query#fragment"},
		{name: "HTTP scheme", endpoint: "@http://resolver.example/dns-query"},
		{name: "TLS path", endpoint: "@tls://resolver.example/dns-query"},
		{name: "TLS query", endpoint: "@tls://resolver.example?profile=one"},
		{name: "TCP path", endpoint: "@tcp://resolver.example/dns-query"},
		{name: "UDP query", endpoint: "@udp://resolver.example?profile=one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := writeExistingDNSOutput(t)
			_, _, err := executeRootStreams(t, "dns", test.endpoint, "example.test", "--output", outputPath)
			require.Error(t, err, "invalid endpoint succeeded")
			assertExistingDNSOutput(t, outputPath)
		})
	}
}

func TestEncryptedDNSRejectsInvalidBareEndpointsBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"@resolver.example/path",
		"@resolver.example?profile=one",
		"@resolver.example#fragment",
		"@user@resolver.example",
	} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			exchanged := false
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
					exchanged = true
					return standardDNSReply(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return []string{"127.0.0.1"}, nil },
			})
			outputPath := writeExistingDNSOutput(t)
			_, _, err := executeRootCommandStreams(t, root, "dns", endpoint, "example.test", "--output", outputPath)
			require.Error(t, err, "invalid bare endpoint succeeded")
			assert.False(t, exchanged, "invalid bare endpoint reached DNS exchange")
			assertExistingDNSOutput(t, outputPath)
		})
	}
}

func TestEncryptedDNSRejectsEmptyQueryDelimiterBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{"udp", "tcp"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			exchanged := false
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
					exchanged = true
					return standardDNSReply(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return []string{"127.0.0.1"}, nil },
			})
			outputPath := writeExistingDNSOutput(t)
			endpoint := "@" + scheme + "://127.0.0.1:9?"
			_, _, err := executeRootCommandStreams(t, root, "dns", endpoint, "example.test", "--output", outputPath)
			require.Error(t, err, "%s endpoint accepted an empty query delimiter", scheme)
			assert.False(t, exchanged, "%s endpoint reached DNS exchange", scheme)
			assertExistingDNSOutput(t, outputPath)
		})
	}

	t.Run("tls", func(t *testing.T) {
		t.Parallel()
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		connected := make(chan bool, 1)
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				connected <- false
				return
			}
			connected <- true
			_ = connection.Close() //nolint:errcheck // connection is deliberately aborted
		}()
		outputPath := writeExistingDNSOutput(t)
		endpoint := "@tls://" + listener.Addr().String() + "?"
		_, _, err = executeRootStreams(t, "dns", endpoint, "example.test", "--insecure", "--output", outputPath)
		_ = listener.Close() //nolint:errcheck // releases the blocked fixture Accept
		require.Error(t, err, "TLS endpoint accepted an empty query delimiter")
		assert.False(t, <-connected, "TLS endpoint opened a connection")
		assertExistingDNSOutput(t, outputPath)
	})
}

func TestDNSPlaintextEndpointSchemes(t *testing.T) {
	t.Parallel()

	t.Run("UDP", func(t *testing.T) {
		t.Parallel()
		host, port, connection, done := startUDPFixture(t, standardDNSReply)
		stdout, _, err := executeRootStreams(t, "dns", "@udp://"+net.JoinHostPort(host, port), "example.test", "--select", "values")
		require.NoError(t, err)
		require.Equal(t, "192.0.2.44\n", stdout)
		finishUDPFixture(t, connection, done)
	})
	t.Run("TCP", func(t *testing.T) {
		t.Parallel()
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
		done := serveTCPAnswerFixture(listener)
		stdout, _, err := executeRootStreams(t, "dns", "@tcp://"+listener.Addr().String(), "fixture.example", "--select", "values")
		require.NoError(t, err)
		require.Equal(t, "192.0.2.45\n", stdout)
		require.NoError(t, <-done)
	})
}

func TestEncryptedDNSDefaultPorts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		endpoint string
		port     string
	}{
		{name: "DoT", endpoint: "@tls://127.0.0.1", port: "853"},
		{name: "DoH", endpoint: "@https://127.0.0.1", port: "443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := executeRootStreams(t, "dns", test.endpoint, "example.test", "--insecure", "--timeout", "100ms")
			require.ErrorContains(t, err, test.port, "default port")
		})
	}
}

func TestEncryptedDNSRejectsTLSFlagsForPlaintextEndpoints(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	tests := []struct {
		name string
		args []string
	}{
		{name: "CA over UDP", args: []string{"@udp://127.0.0.1:9", "--ca", identity.caCertPath}},
		{name: "system CA over TCP", args: []string{"@tcp://127.0.0.1:9", "--ca", identity.caCertPath, "--system-ca"}},
		{name: "server name over bare UDP", args: []string{"@127.0.0.1:9", "--servername", "localhost"}},
		{name: "client certificate over UDP", args: []string{"@udp://127.0.0.1:9", "--cert", identity.clientCertPath, "--key", identity.clientKeyPath}},
		{name: "insecure over TCP", args: []string{"@tcp://127.0.0.1:9", "--insecure"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"dns", test.args[0], "example.test"}, test.args[1:]...)
			exchanged := false
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
					exchanged = true
					return standardDNSReply(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return []string{"127.0.0.1"}, nil },
			})
			_, _, err := executeRootCommandStreams(t, root, args...)
			require.Error(t, err, "plaintext endpoint accepted TLS flags")
			assert.False(t, exchanged, "plaintext endpoint reached DNS exchange before rejecting TLS flags")
		})
	}
}

func TestEncryptedDNSRejectsConflictingTLSOptionsBeforeNetwork(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	tests := []struct {
		name string
		args []string
	}{
		{name: "system roots without custom CA", args: []string{"--system-ca"}},
		{name: "insecure and custom CA", args: []string{"--insecure", "--ca", identity.caCertPath}},
		{name: "insecure and system roots", args: []string{"--insecure", "--ca", identity.caCertPath, "--system-ca"}},
		{name: "certificate without key", args: []string{"--cert", identity.clientCertPath}},
		{name: "key without certificate", args: []string{"--key", identity.clientKeyPath}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)
			connected := make(chan bool, 1)
			go func() {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					connected <- false
					return
				}
				connected <- true
				_ = connection.Close() //nolint:errcheck // connection is deliberately aborted
			}()
			args := append([]string{"dns", "@tls://" + listener.Addr().String(), "example.test"}, test.args...)
			_, _, err = executeRootStreams(t, args...)
			_ = listener.Close() //nolint:errcheck // releases a blocked fixture Accept
			require.Error(t, err, "conflicting TLS options reached the network")
			assert.False(t, <-connected, "conflicting TLS options opened a network connection")
		})
	}
}

func TestEncryptedDNSExplicitSystemResolverConflictsWithDirectOptions(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	tests := [][]string{
		{"--port", "853"},
		{"--ca", identity.caCertPath},
		{"--servername", "localhost"},
		{"--insecure"},
	}
	for _, extra := range tests {
		name := strings.Join(extra, " ")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			args := []string{"dns", "example.test", "--resolver", "system"}
			if strings.HasPrefix(extra[0], "@") {
				args = []string{"dns", extra[0], "example.test", "--resolver", "system"}
			} else {
				args = append(args, extra...)
			}
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
				}},
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
					return standardDNSReply(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return []string{"127.0.0.1"}, nil },
			})
			_, _, err := executeRootCommandStreams(t, root, args...)
			assert.Error(t, err, "explicit system resolver accepted direct-DNS options")
		})
	}
}

func TestDNSOverTLSTrustServerNameInsecureAndSystemRoots(t *testing.T) {
	t.Parallel()

	tests := []struct { //nolint:govet // field order keeps table entries readable
		name         string
		identityName string
		args         func(encryptedDNSTestIdentity) []string
	}{
		{name: "custom root", identityName: "localhost", args: func(identity encryptedDNSTestIdentity) []string { return []string{"--ca", identity.caCertPath} }},
		{name: "custom plus system roots", identityName: "localhost", args: func(identity encryptedDNSTestIdentity) []string {
			return []string{"--ca", identity.caCertPath, "--system-ca"}
		}},
		{name: "server name override", identityName: "resolver.test", args: func(identity encryptedDNSTestIdentity) []string {
			return []string{"--ca", identity.caCertPath, "--servername", "resolver.test"}
		}},
		{name: "insecure", identityName: "untrusted.test", args: func(encryptedDNSTestIdentity) []string { return []string{"--insecure"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity := newEncryptedDNSTestIdentity(t, []string{test.identityName}, nil)
			endpoint, requests := startDoTTestServer(t, identity, false, standardDNSReply)
			args := append([]string{"dns", endpoint, "example.test", "--select", "values"}, test.args(identity)...)
			stdout, _, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			require.Equal(t, "192.0.2.44\n", stdout)
			require.NoError(t, (<-requests).err)
		})
	}
}

func TestDNSOverTLSRejectsUntrustedCertificateWithoutDowngrade(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	other := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	endpoint, requests := startDoTTestServer(t, identity, false, standardDNSReply)
	outputPath := writeExistingDNSOutput(t)
	_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", other.caCertPath, "--output", outputPath)
	require.Error(t, err, "DoT accepted an untrusted server certificate")
	assertExistingDNSOutput(t, outputPath)
	select {
	case got := <-requests:
		if got.err == nil {
			t.Fatalf("server received a plaintext DNS request after TLS verification failed: %+v", got)
		}
	default:
	}
}

func TestEncryptedDNSNeverDowngradesToPlaintext(t *testing.T) {
	t.Parallel()

	t.Run("DoT", func(t *testing.T) {
		t.Parallel()
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		firstBytes := make(chan byte, 2)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				_ = connection.SetReadDeadline(time.Now().Add(time.Second)) //nolint:errcheck // read outcome is asserted below
				var first [1]byte
				if _, readErr := io.ReadFull(connection, first[:]); readErr == nil {
					firstBytes <- first[0]
				}
				_ = connection.Close() //nolint:errcheck // fixture connection is disposable
			}
		}()
		_, _, err = executeRootStreams(t, "dns", "@tls://"+listener.Addr().String(), "example.test", "--insecure", "--timeout", "500ms")
		_ = listener.Close() //nolint:errcheck // releases the fixture accept loop
		<-done
		close(firstBytes)
		require.Error(t, err, "DoT endpoint succeeded against a plaintext server")
		var observed []byte
		for value := range firstBytes {
			observed = append(observed, value)
		}
		require.Equal(t, []byte{0x16}, observed, "one TLS handshake and no plaintext retry")
	})
	t.Run("DoH", func(t *testing.T) {
		t.Parallel()
		var handlerHits atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handlerHits.Add(1)
		}))
		t.Cleanup(server.Close)
		endpoint := "@https://" + strings.TrimPrefix(server.URL, "http://")
		_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--insecure", "--timeout", "500ms")
		require.Error(t, err, "DoH plaintext-server error")
		assert.NotContains(t, err.Error(), "unknown flag", "DoH plaintext-server error")
		assert.Zero(t, handlerHits.Load(), "plaintext HTTP handler hits")
	})
}

func TestDNSOverTLSMutualAuthentication(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	endpoint, requests := startDoTTestServer(t, identity, true, standardDNSReply)
	stdout, _, err := executeRootStreams(
		t,
		"dns", endpoint, "example.test", "--select", "values",
		"--ca", identity.caCertPath,
		"--cert", identity.clientCertPath,
		"--key", identity.clientKeyPath,
	)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.44\n", stdout)
	got := <-requests
	require.NoError(t, got.err, "mTLS request")
	assert.NotZero(t, got.peerCertificates, "mTLS peer certificates")
}

func TestDNSOverTLSParentCancellationAfterRequest(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	requestRead := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	defer release()
	endpoint, serverResult := startDoTTestServer(t, identity, false, func(request *dns.Msg) *dns.Msg {
		requestRead <- struct{}{}
		<-releaseResponse
		return standardDNSReply(request)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)
	outputPath := writeExistingDNSOutput(t)
	commandResult := make(chan error, 1)
	go func() {
		_, _, err := executeRootCommandStreams(
			t,
			root,
			"dns", endpoint, "example.test", "--ca", identity.caCertPath, "--timeout", "0", "--output", outputPath,
		)
		commandResult <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		cancel()
		release()
		select {
		case err := <-commandResult:
			t.Fatalf("DoT fixture did not consume the request; command result = %v", err)
		case <-time.After(time.Second):
			t.Fatal("DoT fixture and command did not stop after cancellation")
		}
	}
	cancel()
	select {
	case err := <-commandResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want parent cancellation", err)
		}
	case <-time.After(500 * time.Millisecond):
		release()
		select {
		case err := <-commandResult:
			t.Fatalf("DoT request remained blocked after cancellation; result after response release = %v", err)
		case <-time.After(time.Second):
			t.Fatal("DoT request remained blocked after cancellation and response release")
		}
	}
	release()
	select {
	case <-serverResult:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("DoT fixture did not stop after cancellation")
	}
	assertExistingDNSOutput(t, outputPath)
}

func TestDNSOverTLSResponseDeadlineIdentity(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	requestRead := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	defer release()
	endpoint, serverResult := startDoTTestServer(t, identity, false, func(request *dns.Msg) *dns.Msg {
		requestRead <- struct{}{}
		<-releaseResponse
		return standardDNSReply(request)
	})
	outputPath := writeExistingDNSOutput(t)
	commandResult := make(chan error, 1)
	started := time.Now()
	go func() {
		_, _, err := executeRootStreams(
			t,
			"dns", endpoint, "example.test", "--ca", identity.caCertPath, "--timeout", "1s", "--output", outputPath,
		)
		commandResult <- err
	}()
	select {
	case <-requestRead:
	case err := <-commandResult:
		release()
		t.Fatalf("DoT command returned before the fixture stalled its response: %v", err)
	case <-time.After(1500 * time.Millisecond):
		release()
		t.Fatal("DoT fixture did not consume the request")
	}
	select {
	case err := <-commandResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want deadline exceeded", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("DoT response deadline took %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("DoT response deadline did not stop the command")
	}
	release()
	select {
	case <-serverResult:
	case <-time.After(time.Second):
		t.Fatal("DoT fixture did not stop after deadline")
	}
	assertExistingDNSOutput(t, outputPath)
}

func TestDNSOverHTTPSRequestDefaultsAndExplicitPath(t *testing.T) { //nolint:tparallel // subtests share an ordered request channel
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	requests := make(chan dohTestRequest, 3)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		requests <- dohTestRequest{method: request.Method, contentType: request.Header.Get("Content-Type"), uri: request.URL.RequestURI(), message: message, err: err}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	// The subtests must consume the shared request channel in command order.
	for _, test := range []struct { //nolint:paralleltest // request observations are consumed in order
		name     string
		path     string
		wantPath string
	}{
		{name: "default", wantPath: "/dns-query"},
		{name: "explicit", path: "/custom/dns?profile=blue&padding=yes", wantPath: "/custom/dns?profile=blue&padding=yes"},
		{name: "explicit empty query", path: "/dns-query?", wantPath: "/dns-query?"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, _, err := executeRootStreams(t, "dns", server.endpoint("localhost", test.path), "example.test", "--ca", identity.caCertPath, "--select", "values")
			require.NoError(t, err)
			require.Equal(t, "192.0.2.44\n", stdout)
			got := <-requests
			require.NoError(t, got.err, "DoH request")
			assert.Equal(t, http.MethodPost, got.method, "DoH method")
			assert.Equal(t, "application/dns-message", got.contentType, "DoH content type")
			assert.Equal(t, test.wantPath, got.uri, "DoH request URI")
		})
	}
}

func TestDNSOverHTTPSMutualAuthentication(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	peerCertificates := make(chan int, 1)
	server := startDoHTestServer(t, identity, true, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peerCertificates <- len(request.TLS.PeerCertificates)
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	stdout, _, err := executeRootStreams(
		t,
		"dns", server.endpoint("localhost", ""), "example.test", "--select", "values",
		"--ca", identity.caCertPath,
		"--cert", identity.clientCertPath,
		"--key", identity.clientKeyPath,
	)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.44\n", stdout)
	assert.NotZero(t, <-peerCertificates, "DoH server received no client certificate")
}

func TestDNSOverHTTPSHonorsEnvironmentProxy(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"resolver.test"}, nil)
	target := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(writer, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		proxyHits.Add(1)
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		upstream, err := (&net.Dialer{}).DialContext(request.Context(), "tcp", target.server.Listener.Addr().String())
		if err != nil {
			_ = client.Close() //nolint:errcheck // original proxy failure is authoritative
			return
		}
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = client.Close()   //nolint:errcheck // original write failure is authoritative
			_ = upstream.Close() //nolint:errcheck // original write failure is authoritative
			return
		}
		go func() {
			_, _ = io.Copy(upstream, client) //nolint:errcheck // tunnel closure is expected
			_ = upstream.Close()             //nolint:errcheck // terminates the paired copy
		}()
		go func() {
			_, _ = io.Copy(client, upstream) //nolint:errcheck // tunnel closure is expected
			_ = client.Close()               //nolint:errcheck // terminates the paired copy
		}()
	}))
	t.Cleanup(proxy.Close)

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestEncryptedDNSDoHProxyChild$", "-test.count=1")
	command.Env = append(os.Environ(),
		"SWYS_DOH_PROXY_CHILD=1",
		"SWYS_DOH_PROXY_ENDPOINT="+target.endpoint("resolver.test", ""),
		"SWYS_DOH_PROXY_CA="+identity.caCertPath,
		"HTTPS_PROXY="+proxy.URL,
		"https_proxy="+proxy.URL,
		"NO_PROXY=",
		"no_proxy=",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("proxied DoH child: %v\n%s", err, output)
	}
	assert.Equal(t, int32(1), proxyHits.Load(), "HTTPS proxy CONNECT count")
}

func TestEncryptedDNSDoHProxyChild(t *testing.T) {
	t.Parallel()

	if os.Getenv("SWYS_DOH_PROXY_CHILD") != "1" {
		return
	}
	stdout, _, err := executeRootStreams(
		t,
		"dns", os.Getenv("SWYS_DOH_PROXY_ENDPOINT"), "example.test", "--select", "values",
		"--ca", os.Getenv("SWYS_DOH_PROXY_CA"),
	)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.44\n", stdout)
}

func TestEncryptedDNSPreservesOutputFormatsAndStatus(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response := standardDNSReply(message)
		response.Rcode = dns.RcodeNameError
		writeDoHTestResponse(t, writer, response)
	}))
	for _, test := range []struct { //nolint:govet // field order keeps table entries readable
		name string
		args []string
		want string
	}{
		{name: "text", want: "Status    NXDOMAIN"},
		{name: "JSON", args: []string{"--format", "json"}, want: `"status": "NXDOMAIN"`},
		{name: "values", args: []string{"--select", "values"}, want: "192.0.2.44\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"dns", server.endpoint("localhost", ""), "example.test", "--ca", identity.caCertPath}
			args = append(args, test.args...)
			stdout, _, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			assert.Contains(t, stdout, test.want)
		})
	}
}

func TestDNSOverHTTPSRejectsEveryRedirectWithoutFollowing(t *testing.T) {
	t.Parallel()

	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	t.Cleanup(target.Close)
	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, err := strconv.Atoi(request.URL.Query().Get("status"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(status)
	}))
	for status := 300; status <= 308; status++ {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			outputPath := writeExistingDNSOutput(t)
			endpoint := server.endpoint("localhost", "/redirect?status="+strconv.Itoa(status))
			_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--output", outputPath)
			require.Error(t, err, "HTTP %d redirect succeeded", status)
			assertExistingDNSOutput(t, outputPath)
		})
	}
	assert.Zero(t, targetHits.Load(), "redirect target hits")
}

func TestDNSOverHTTPSAcceptsSuccessfulStatuses(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		status, err := strconv.Atoi(request.URL.Query().Get("status"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponseWithStatus(t, writer, standardDNSReply(message), status)
	}))
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusIMUsed, 299} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			endpoint := server.endpoint("localhost", "/dns-query?status="+strconv.Itoa(status))
			stdout, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--select", "values")
			require.NoError(t, err, "HTTP %d DoH response", status)
			assert.Equal(t, "192.0.2.44\n", stdout, "HTTP %d", status)
		})
	}
}

func TestDNSOverHTTPSRejectsInvalidHTTPResponsesBeforeOutput(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/wrong-media-type":
			message, err := readDoHTestRequest(request)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			response := standardDNSReply(message)
			if err := response.Pack(); err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write(response.Data) //nolint:errcheck // the client validates the resulting response
		default:
			http.Error(writer, "upstream failed", http.StatusInternalServerError)
		}
	}))
	for _, path := range []string{"/wrong-media-type", "/server-error"} {
		outputPath := writeExistingDNSOutput(t)
		_, _, err := executeRootStreams(t, "dns", server.endpoint("localhost", path), "example.test", "--ca", identity.caCertPath, "--output", outputPath)
		require.Error(t, err, "invalid HTTP response from %s succeeded", path)
		assertExistingDNSOutput(t, outputPath)
	}
}

func TestDNSOverHTTPSResponseSizeLimit(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		size, err := strconv.Atoi(request.URL.Query().Get("size"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		wire, err := packedDNSReplyOfSize(message, min(size, dns.MaxMsgSize))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		if size > len(wire) {
			wire = append(wire, make([]byte, size-len(wire))...)
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(wire) //nolint:errcheck // the client validates the resulting response
	}))
	for _, size := range []int{dns.MaxMsgSize - 1, dns.MaxMsgSize, dns.MaxMsgSize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			outputPath := writeExistingDNSOutput(t)
			endpoint := server.endpoint("localhost", "/dns-query?size="+strconv.Itoa(size))
			stdout, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--select", "values", "--output", outputPath)
			if size <= dns.MaxMsgSize {
				require.NoError(t, err)
				require.Empty(t, stdout, "want file output")
				data, readErr := os.ReadFile(outputPath)
				require.NoError(t, readErr, "read file output")
				assert.Equal(t, "192.0.2.44\n", string(data), "file output")
				return
			}
			require.Error(t, err, "oversized DoH response succeeded")
			assertExistingDNSOutput(t, outputPath)
		})
	}
}

func TestPackedDNSReplyBoundaryFixture(t *testing.T) {
	t.Parallel()

	request := dns.NewMsg("example.test", dns.TypeA)
	for _, size := range []int{dns.MaxMsgSize - 1, dns.MaxMsgSize} {
		wire, err := packedDNSReplyOfSize(request, size)
		require.NoError(t, err)
		require.Len(t, wire, size, "packed DNS reply fixture")
		message := &dns.Msg{Data: wire}
		require.NoError(t, message.Unpack(), "unpack %d-byte fixture", size)
	}
}

func TestEncryptedDNSReplyValidationPreservesOutput(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	invalidReply := func(request *dns.Msg) *dns.Msg {
		response := standardDNSReply(request)
		response.Question = dns.NewMsg("other.test", dns.TypeA).Question
		return response
	}
	dotEndpoint, dotRequests := startDoTTestServer(t, identity, false, invalidReply)
	dohServer := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, invalidReply(message))
	}))
	for _, endpoint := range []string{dotEndpoint, dohServer.endpoint("localhost", "")} {
		outputPath := writeExistingDNSOutput(t)
		_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--output", outputPath)
		require.ErrorIs(t, err, errDNSResponseMismatch, "mismatched reply from %s", endpoint)
		assertExistingDNSOutput(t, outputPath)
	}
	select {
	case got := <-dotRequests:
		if got.err != nil {
			t.Fatal(got.err)
		}
	default:
	}
}

func TestEncryptedDNSExplicitPortAgreement(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	var hits atomic.Int32
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	port := server.port()
	stdout, _, err := executeRootStreams(t,
		"dns", server.endpoint("localhost", ""), "example.test",
		"--port", port, "--ca", identity.caCertPath, "--select", "values")
	require.NoError(t, err, "agreeing port")
	require.Equal(t, "192.0.2.44\n", stdout, "agreeing port")
	before := hits.Load()
	_, _, err = executeRootStreams(t, "dns", server.endpoint("localhost", ""), "example.test", "--port", differentPort(port), "--ca", identity.caCertPath)
	require.Error(t, err, "conflicting explicit ports succeeded")
	assert.Equal(t, before, hits.Load(), "server hits after port conflict")
}

func TestEncryptedDNSAliases(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	for _, command := range []string{"dns", "dig", "nslookup"} {
		stdout, _, err := executeRootStreams(t, command, server.endpoint("localhost", ""), "example.test", "--ca", identity.caCertPath, "--select", "values")
		require.NoError(t, err, "%s", command)
		require.Equal(t, "192.0.2.44\n", stdout, "%s", command)
	}
}

func TestEncryptedDNSOverallTimeouts(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	t.Run("TLS handshake", func(t *testing.T) {
		t.Parallel()
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
		done := make(chan struct{})
		go func() {
			defer close(done)
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer connection.Close()               //nolint:errcheck // test connection cleanup is best effort
			_, _ = io.Copy(io.Discard, connection) //nolint:errcheck // closure is the expected result
		}()
		started := time.Now()
		_, _, err = executeRootStreams(t, "dns", "@tls://"+listener.Addr().String(), "example.test", "--insecure", "--timeout", "50ms")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("TLS timeout: elapsed = %s, err = %v", time.Since(started), err)
		}
		_ = listener.Close() //nolint:errcheck // releases the fixture goroutine
		<-done
	})
	t.Run("HTTPS response", func(t *testing.T) {
		t.Parallel()
		releaseHandler := make(chan struct{})
		defer close(releaseHandler)
		handlerEntered := make(chan error, 1)
		server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, readErr := readDoHTestRequest(request)
			handlerEntered <- readErr
			if readErr != nil {
				http.Error(writer, readErr.Error(), http.StatusBadRequest)
				return
			}
			// Returning on client cancellation lets net/http synthesize an empty 200 response.
			<-releaseHandler
		}))
		started := time.Now()
		commandResult := make(chan error, 1)
		go func() {
			_, _, err := executeRootStreams(
				t,
				"dns", server.endpoint("localhost", ""), "example.test", "--ca", identity.caCertPath, "--timeout", "1s",
			)
			commandResult <- err
		}()
		select {
		case readErr := <-handlerEntered:
			if readErr != nil {
				t.Fatalf("read timed DoH request: %v", readErr)
			}
		case err := <-commandResult:
			t.Fatalf("DoH command returned before the handler stalled its response: %v", err)
		case <-time.After(1500 * time.Millisecond):
			t.Fatal("timed DoH request did not reach the response handler")
		}
		select {
		case err := <-commandResult:
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
				t.Fatalf("DoH timeout: elapsed = %s, err = %v", time.Since(started), err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("DoH response timeout did not stop the command")
		}
	})
}

func TestEncryptedDNSParentCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	root := newRootCmd()
	root.SetContext(ctx)
	_, _, err := executeRootCommandStreams(t, root, "dns", "@tls://127.0.0.1:853", "example.test", "--insecure", "--timeout", "0")
	require.ErrorIs(t, err, context.Canceled)
}

type encryptedDNSTestIdentity struct { //nolint:govet // named fields match the fixture roles
	caCertPath     string
	serverCert     tls.Certificate
	clientCertPath string
	clientKeyPath  string
	clientRoots    *x509.CertPool
}

//nolint:unparam // IP SAN input keeps the certificate fixture explicit.
func newEncryptedDNSTestIdentity(
	tb testing.TB,
	dnsNames []string,
	ipAddresses []net.IP,
) encryptedDNSTestIdentity {
	tb.Helper()
	now := time.Now()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "encrypted DNS test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		tb.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "encrypted DNS test server"}, DNSNames: dnsNames, IPAddresses: ipAddresses,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, serverPublic, rootPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "encrypted DNS test client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, root, clientPublic, rootPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	directory := tb.TempDir()
	rootPath := filepath.Join(directory, "ca.pem")
	clientCertPath := filepath.Join(directory, "client.pem")
	clientKeyPath := filepath.Join(directory, "client-key.pem")
	writePEMTestFile(tb, rootPath, "CERTIFICATE", rootDER)
	writePEMTestFile(tb, clientCertPath, "CERTIFICATE", clientDER)
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	writePEMTestFile(tb, clientKeyPath, "PRIVATE KEY", clientKeyDER)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(root)
	return encryptedDNSTestIdentity{
		caCertPath:     rootPath,
		serverCert:     tls.Certificate{Certificate: [][]byte{serverDER, rootDER}, PrivateKey: serverPrivate},
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
		clientRoots:    clientRoots,
	}
}

func writePEMTestFile(tb testing.TB, path, blockType string, data []byte) {
	tb.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data}), 0o600); err != nil {
		tb.Fatal(err)
	}
}

type dotTestResult struct { //nolint:govet // result fields follow protocol order
	request          *dns.Msg
	peerCertificates int
	err              error
}

//nolint:gocritic // Identity is immutable fixture state.
func startDoTTestServer(
	t *testing.T,
	identity encryptedDNSTestIdentity,
	requireClient bool,
	reply func(*dns.Msg) *dns.Msg,
) (string, <-chan dotTestResult) {
	t.Helper()
	baseListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{identity.serverCert}, MinVersion: tls.VersionTLS12}
	if requireClient {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = identity.clientRoots
	}
	listener := tls.NewListener(baseListener, config)
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
	results := make(chan dotTestResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			results <- dotTestResult{err: err}
			return
		}
		defer connection.Close() //nolint:errcheck // test connection cleanup is best effort
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			results <- dotTestResult{err: errNonTLSConnection}
			return
		}
		if err := tlsConnection.HandshakeContext(t.Context()); err != nil {
			results <- dotTestResult{err: err}
			return
		}
		reader := bufio.NewReader(tlsConnection)
		lengthBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, lengthBytes); err != nil {
			results <- dotTestResult{err: err}
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
		if _, err := io.ReadFull(reader, wire); err != nil {
			results <- dotTestResult{err: err}
			return
		}
		request := &dns.Msg{Data: wire}
		if err := request.Unpack(); err != nil {
			results <- dotTestResult{err: err}
			return
		}
		response := reply(request)
		if err := response.Pack(); err != nil {
			results <- dotTestResult{request: request, err: err}
			return
		}
		framed := make([]byte, 2+len(response.Data))
		binary.BigEndian.PutUint16(framed, uint16(len(response.Data)))
		copy(framed[2:], response.Data)
		_, err = tlsConnection.Write(framed)
		results <- dotTestResult{request: request, peerCertificates: len(tlsConnection.ConnectionState().PeerCertificates), err: err}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = host
	return "@tls://localhost:" + port, results
}

type dohTestServer struct {
	server *httptest.Server
}

//nolint:gocritic // Identity is immutable fixture state.
func startDoHTestServer(
	tb testing.TB,
	identity encryptedDNSTestIdentity,
	requireClient bool,
	handler http.Handler,
) dohTestServer {
	tb.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity.serverCert}, MinVersion: tls.VersionTLS12}
	if requireClient {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = identity.clientRoots
	}
	server.StartTLS()
	tb.Cleanup(server.Close)
	return dohTestServer{server: server}
}

func (server dohTestServer) endpoint(host, path string) string {
	_, port, err := net.SplitHostPort(server.server.Listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return "@https://" + net.JoinHostPort(host, port) + path
}

func (server dohTestServer) port() string {
	_, port, err := net.SplitHostPort(server.server.Listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return port
}

type dohTestRequest struct { //nolint:govet // request fields follow wire-observation order
	method      string
	contentType string
	uri         string
	message     *dns.Msg
	err         error
}

func readDoHTestRequest(request *http.Request) (*dns.Msg, error) {
	if request.Method != http.MethodPost {
		return nil, fmt.Errorf("%w: got %s", errUnexpectedDoHMethod, request.Method)
	}
	if request.Header.Get("Content-Type") != "application/dns-message" {
		return nil, fmt.Errorf("%w: got %q", errUnexpectedDoHContentType, request.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH test request: %w", err)
	}
	if len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("%w: %d bytes", errDoHTestRequestTooLarge, len(body))
	}
	message := &dns.Msg{Data: body}
	if err := message.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack DoH test request: %w", err)
	}
	return message, nil
}

func writeDoHTestResponse(tb testing.TB, writer http.ResponseWriter, response *dns.Msg) {
	tb.Helper()
	writeDoHTestResponseWithStatus(tb, writer, response, http.StatusOK)
}

func writeDoHTestResponseWithStatus(tb testing.TB, writer http.ResponseWriter, response *dns.Msg, status int) {
	tb.Helper()
	if err := response.Pack(); err != nil {
		tb.Errorf("pack DoH response: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/dns-message")
	writer.WriteHeader(status)
	if _, err := writer.Write(response.Data); err != nil {
		tb.Errorf("write DoH response: %v", err)
	}
}

func standardDNSReply(request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	dnsutil.SetReply(response, request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: request.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.44")},
	}}
	return response
}

func packedDNSReplyOfSize(request *dns.Msg, size int) ([]byte, error) {
	response := standardDNSReply(request)
	padding := &dns.NULL{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}, NULL: rdata.NULL{}}
	response.Extra = []dns.RR{padding}
	if err := response.Pack(); err != nil {
		return nil, fmt.Errorf("pack base DNS fixture: %w", err)
	}
	remaining := size - len(response.Data)
	if remaining < 0 {
		return nil, fmt.Errorf("%w: target %d, base %d", errDNSFixtureTargetTooSmall, size, len(response.Data))
	}
	padding.Null = strings.Repeat("p", remaining)
	if err := response.Pack(); err != nil {
		return nil, fmt.Errorf("pack padded DNS fixture: %w", err)
	}
	if len(response.Data) != size {
		return nil, fmt.Errorf("%w: got %d, want %d", errDNSFixtureLengthMismatch, len(response.Data), size)
	}
	return append([]byte(nil), response.Data...), nil
}

func writeExistingDNSOutput(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "result.txt")
	require.NoError(t, os.WriteFile(path, []byte("keep existing output\n"), 0o600))
	return path
}

func assertExistingDNSOutput(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "keep existing output\n", string(data), "existing output")
}

func differentPort(port string) string {
	parsed, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	if parsed == 65535 {
		return "65534"
	}
	return strconv.Itoa(parsed + 1)
}

func TestDNSOverHTTPSAllowsEncodedCredentialStdin(t *testing.T) {
	t.Parallel()
	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	ca, err := os.ReadFile(identity.caCertPath)
	require.NoError(t, err)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, readErr := readDoHTestRequest(request)
		if readErr != nil {
			http.Error(writer, "invalid DNS request", http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))
	root := newRootCmd()
	root.SetIn(strings.NewReader(base64.StdEncoding.EncodeToString(ca)))
	stdout, stderr, err := executeRootCommandStreams(t, root,
		"dns", "example.test", server.endpoint("localhost", ""), "A", server.endpoint("localhost", ""),
		"--ca", "-", "--ca-encoding", "base64", "--select", "values", "--timeout", "2s")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.44\n192.0.2.44\n", stdout)
	assert.Empty(t, stderr)
}

func TestDNSTLSArtifactValidationPrecedesIO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		endpoint string
		flags    []string
		unknown  bool
	}{
		{name: "explicit raw needs source", endpoint: "@tls://127.0.0.1:9", flags: []string{"--ca-encoding", "raw"}},
		{name: "unknown codec", endpoint: "@https://127.0.0.1:9", flags: []string{"--ca", "missing", "--ca-encoding", "invalid"}, unknown: true},
		{name: "UDP codec", endpoint: "@udp://127.0.0.1:9", flags: []string{"--ca", "missing", "--ca-encoding", "raw"}},
		{name: "TCP codec", endpoint: "@tcp://127.0.0.1:9", flags: []string{"--ca", "missing", "--ca-encoding", "raw"}},
		{name: "later invalid endpoint", endpoint: "@tls://127.0.0.1:9", flags: []string{"@", "--ca", "-"}},
		{name: "mixed plaintext with credentials", endpoint: "@tls://127.0.0.1:9", flags: []string{"@127.0.0.1:9", "--ca", "-"}},
		{name: "two credentials", endpoint: "@tls://127.0.0.1:9", flags: []string{"--ca", "-", "--cert", "-", "--key", "missing"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(context.Context, *dns.Msg, dnsquery.Transport, string) (*dns.Msg, error) {
					t.Error("invalid credentials reached DNS exchange")
					return nil, errUnexpectedSystemLookup
				},
			})
			input := strings.NewReader("must not be consumed")
			root.SetIn(input)
			output := writeExistingDNSOutput(t)
			args := append([]string{"dns", test.endpoint, "example.test", "--output", output}, test.flags...)
			stdout, _, err := executeRootCommandStreams(t, root, args...)
			require.Error(t, err)
			if test.unknown {
				require.ErrorIs(t, err, encoding.ErrUnknownInputEncoding)
			} else {
				require.ErrorIs(t, err, errInvalidDNSOptions)
			}
			assert.Equal(t, len("must not be consumed"), input.Len(), "credential input consumed before validation")
			assert.Empty(t, stdout)
			assertExistingDNSOutput(t, output)
		})
	}
}
