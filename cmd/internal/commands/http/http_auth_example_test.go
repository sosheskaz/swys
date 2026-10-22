package http_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPBearerTokenFromFile(t *testing.T) {
	t.Parallel()
	server, caPath, received := startHTTPAuthServer(t)
	tokenPath := filepath.Join(t.TempDir(), "token")
	// Files written by echo or an editor end in a newline; one is trimmed.
	require.NoError(t, os.WriteFile(tokenPath, []byte("example-token\n"), 0o600))

	stdout, stderr, err := executeRootStreams(t, "http", server.URL, "--ca", caPath, "--auth-bearer-file", tokenPath)
	require.NoError(t, err)
	assert.Equal(t, "authorized", stdout)
	assert.Empty(t, stderr)
	assert.Equal(t, []string{"Bearer example-token"}, <-received)
}

func TestExampleHTTPBasicAuthFromEnvironment(t *testing.T) {
	t.Setenv("SWYS_EXAMPLE_BASIC", "deploy:s3cret:with-colon")
	server, caPath, received := startHTTPAuthServer(t)

	_, _, err := executeRootStreams(t, "http", server.URL, "--ca", caPath, "--auth-basic-env", "SWYS_EXAMPLE_BASIC")
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{"Authorization": <-received}}
	user, password, ok := request.BasicAuth()
	require.True(t, ok, "server received Basic credentials")
	assert.Equal(t, "deploy", user)
	assert.Equal(t, "s3cret:with-colon", password, "only the first colon separates the user")
}

func TestExampleHTTPCleartextAuthRequiresOptIn(t *testing.T) {
	t.Parallel()
	received := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Values("Authorization")
		writeHTTPTestString(t, writer, "cleartext")
	}))
	t.Cleanup(server.Close)

	_, _, err := executeRootStreams(t, "http", server.URL, "--auth-bearer", "local-token")
	require.ErrorIs(t, err, errInvalidHTTPFlags, "credentials over http:// need an explicit opt-in")
	assert.Empty(t, received, "the refused credential reached the server")

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--auth-bearer", "local-token", "--insecure-cleartext-auth")
	require.NoError(t, err)
	assert.Equal(t, "cleartext", stdout)
	assert.Equal(t, []string{"Bearer local-token"}, <-received)
}

// startHTTPAuthServer records each request's Authorization values behind a trusted test CA.
func startHTTPAuthServer(t *testing.T) (*httptest.Server, string, <-chan []string) {
	t.Helper()
	received := make(chan []string, 4)
	server, caPath := startTrustedHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Values("Authorization")
		writeHTTPTestString(t, writer, "authorized")
	}))
	return server, caPath, received
}

func startTrustedHTTPServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	return server, caPath
}
