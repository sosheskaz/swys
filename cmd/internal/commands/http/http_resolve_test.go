package http_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPResolveFallsBackAndTracesMappedAddresses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "fallback")
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port := serverURL.Port()
	requestHost := net.JoinHostPort("127.0.0.2", port)
	resolve := requestHost + ":127.0.0.3," + serverURL.Hostname()

	stdout, _, err := executeRootStreams(
		t,
		"http", "http://"+requestHost,
		"--resolve", resolve,
		"--format", "json", "--trace",
	)
	require.NoError(t, err)
	envelope := decodeHTTPEnvelope(t, stdout)
	if envelope.Body != base64.StdEncoding.EncodeToString([]byte("fallback")) {
		t.Fatalf("body = %q", envelope.Body)
	}
	var trace []struct {
		DNS      string `json:"dns"`
		Address  string `json:"address"`
		Attempts []struct {
			Address  string `json:"address"`
			Selected bool   `json:"selected"`
		} `json:"connect_attempts"`
	}
	require.NoError(t, json.Unmarshal(envelope.Trace, &trace))
	if len(trace) != 1 || trace[0].DNS != "" || trace[0].Address != serverURL.Host {
		t.Fatalf("trace = %+v", trace)
	}
	wantAttempts := []string{net.JoinHostPort("127.0.0.3", port), serverURL.Host}
	if len(trace[0].Attempts) != len(wantAttempts) {
		t.Fatalf("attempts = %+v", trace[0].Attempts)
	}
	for index, want := range wantAttempts {
		attempt := trace[0].Attempts[index]
		if attempt.Address != want || attempt.Selected != (index == len(wantAttempts)-1) {
			t.Fatalf("attempt %d = %+v, want address %q", index, attempt, want)
		}
	}
}

func TestHTTPResolveAppliesToRedirects(t *testing.T) {
	t.Parallel()

	finalHost := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			_, port, err := net.SplitHostPort(request.Host)
			if err != nil {
				t.Errorf("split request host: %v", err)
				return
			}
			writer.Header().Set("Location", "http://"+net.JoinHostPort("127.0.0.2", port)+"/final")
			writer.WriteHeader(http.StatusFound)
			return
		}
		finalHost <- request.Host
		writeHTTPTestString(t, writer, "redirected")
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	redirectHost := net.JoinHostPort("127.0.0.2", serverURL.Port())
	resolve := redirectHost + ":" + serverURL.Hostname()

	stdout, _, err := executeRootStreams(t, "http", server.URL+"/start", "--resolve", resolve)
	require.NoError(t, err)
	assert.Equal(t, "redirected", stdout)
	if host := <-finalHost; host != redirectHost {
		t.Fatalf("redirect Host = %q, want %q", host, redirectHost)
	}
}

func TestHTTPResolvePreservesTLSURLIdentity(t *testing.T) {
	t.Parallel()

	caCert, serverCert, serverKey := createHTTPResolveTestIdentity(t, "127.0.0.2")
	identity, err := tls.LoadX509KeyPair(serverCert, serverKey)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "verified")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	requestHost := net.JoinHostPort("127.0.0.2", serverURL.Port())
	resolve := requestHost + ":" + serverURL.Hostname()

	stdout, _, err := executeRootStreams(
		t,
		"http", "https://"+requestHost,
		"--resolve", resolve,
		"--ca", caCert,
	)
	require.NoError(t, err)
	assert.Equal(t, "verified", stdout)
}

func TestHTTPResolveRejectsInvalidRuleBeforeIO(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "response")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	input := &countingReader{source: strings.NewReader("unread")}
	_, _, err := executeHTTPStreamsWithInput(
		t,
		input,
		"http", "http://127.0.0.1:1",
		"--resolve", "invalid",
		"--output", outputPath,
	)
	require.ErrorIs(t, err, errInvalidHTTPFlags)
	if input.reads.Load() != 0 {
		t.Fatal("invalid resolve rule read stdin")
	}
	contents, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	if string(contents) != "preserve" {
		t.Fatalf("output = %q, want preserved contents", contents)
	}
}

func TestHTTPResolveReportsEveryFailedAddress(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	requestHost := net.JoinHostPort("127.0.0.4", port)
	resolve := requestHost + ":127.0.0.2,127.0.0.3"

	_, _, err = executeRootStreams(t, "http", "http://"+requestHost, "--resolve", resolve, "--timeout", "1s")
	require.Error(t, err)
	for _, address := range []string{net.JoinHostPort("127.0.0.2", port), net.JoinHostPort("127.0.0.3", port)} {
		assert.Contains(t, err.Error(), address)
	}
}

func createHTTPResolveTestIdentity(t *testing.T, ipAddress string) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	caKey := filepath.Join(directory, "ca.key")
	caCert := filepath.Join(directory, "ca.crt")
	serverKey := filepath.Join(directory, "server.key")
	serverCert := filepath.Join(directory, "server.crt")
	generateTestKey(t, "ed25519", caKey)
	generateTestKey(t, "ed25519", serverKey)
	commands := [][]string{
		{"cert", "create", "--ca", "--subject", "CN=resolve-test-ca", "--key", caKey, "--output", caCert},
		{
			"cert", "create", "--ip", ipAddress, "--server-only", "--key", serverKey,
			"--issuer-cert", caCert, "--issuer-key", caKey, "--output", serverCert,
		},
	}
	for _, arguments := range commands {
		if _, _, err := executeRootStreams(t, arguments...); err != nil {
			t.Fatalf("execute %v: %v", arguments, err)
		}
	}
	return caCert, serverCert, serverKey
}
