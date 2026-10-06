package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "unexpected method", http.StatusBadRequest)
			return
		}
		if _, err := io.WriteString(writer, "hello from server\n"); err != nil {
			t.Errorf("write example response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL)
	require.NoError(t, err, "swys http URL: %v", err)
	assert.Equal(t, "hello from server\n", stdout)
	assert.Empty(t, stderr)
}

func TestExampleHTTPPostJSON(t *testing.T) {
	t.Parallel()

	type receivedRequest struct {
		method      string
		contentType string
		body        string
	}
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		received <- receivedRequest{method: request.Method, contentType: request.Header.Get("Content-Type"), body: string(body)}
		writer.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(writer, "created\n"); err != nil {
			t.Errorf("write example response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(
		t,
		"http", server.URL,
		"-j", `{"name":"demo"}`,
	)
	require.NoError(t, err, "swys http -j: %v", err)
	assert.Equal(t, "created\n", stdout)
	assert.Empty(t, stderr)

	request := <-received
	assert.Equal(t, http.MethodPost, request.method, "explicit JSON body implies POST")
	if request.contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", request.contentType)
	}
	if strings.TrimSpace(request.body) != `{"name":"demo"}` {
		t.Fatalf("body = %q, want JSON document", request.body)
	}
}

func TestExampleHTTPDefaultsToHTTPS(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.URL.RequestURI() != "/whoami?demo=yes" {
			t.Errorf("unexpected request: TLS=%t URI=%q", request.TLS != nil, request.URL.RequestURI())
		}
		writeHTTPTestString(t, writer, "hello over TLS")
	}))
	t.Cleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "https://") + "/whoami?demo=yes"
	stdout, _, err := executeRootStreams(t, "http", address, "--insecure")
	require.NoError(t, err)
	assert.Equal(t, "hello over TLS", stdout)
}
