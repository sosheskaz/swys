package dns_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleDNSOverTLS(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	endpoint, requests := startDoTTestServer(t, identity, false, standardDNSReply)

	stdout, stderr, err := executeRootStreams(
		t,
		"dns", endpoint, "example.test", "A",
		"--ca", identity.caCertPath,
		"--select", "values",
	)
	require.NoError(t, err, "swys dns @tls://server name A")
	require.Equal(t, "192.0.2.44\n", stdout)
	require.Empty(t, stderr)
	got := <-requests
	require.NoError(t, got.err, "DoT request")
	require.NotNil(t, got.request, "DoT request")
	require.NotEmpty(t, got.request.Question, "DoT request question")
	assert.Equal(t, "example.test.", got.request.Question[0].Header().Name)
}

func TestExampleDNSOverHTTPS(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	requests := make(chan dohTestRequest, 1)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		requests <- dohTestRequest{method: request.Method, contentType: request.Header.Get("Content-Type"), uri: request.URL.RequestURI(), message: message, err: err}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))

	stdout, stderr, err := executeRootStreams(
		t,
		"dns", server.endpoint("localhost", "/lookup?profile=example"), "example.test",
		"--ca", identity.caCertPath,
		"--select", "values",
	)
	require.NoError(t, err, "swys dns @https://server/lookup?profile=example name")
	require.Equal(t, "192.0.2.44\n", stdout)
	require.Empty(t, stderr)
	got := <-requests
	require.NoError(t, got.err, "DoH request")
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "application/dns-message", got.contentType)
	assert.Equal(t, "/lookup?profile=example", got.uri)
}
