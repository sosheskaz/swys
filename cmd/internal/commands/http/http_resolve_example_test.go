package http_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPResolve(t *testing.T) {
	t.Parallel()

	receivedHost := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedHost <- request.Host
		writeHTTPTestString(t, writer, "resolved")
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port := serverURL.Port()
	requestHost := net.JoinHostPort("127.0.0.2", port)
	resolve := requestHost + ":" + serverURL.Hostname()

	stdout, stderr, err := executeRootStreams(
		t,
		"http", "http://"+requestHost,
		"--resolve", resolve,
	)
	require.NoError(t, err, "swys http --resolve: %v", err)
	assert.Equal(t, "resolved", stdout)
	assert.Empty(t, stderr)
	if host := <-receivedHost; host != requestHost {
		t.Fatalf("Host = %q, want original URL host %q", host, requestHost)
	}
}
