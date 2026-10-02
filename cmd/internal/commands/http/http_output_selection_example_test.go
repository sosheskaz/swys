package http_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPOutputSelection(t *testing.T) {
	t.Parallel()

	body := []byte{'{', '"', 'n', '"', ':', '1', '}', '\n', 0x00, 0xff}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-NPC-Test", "selected")
		if request.URL.Path == "/application-json" {
			writer.Header().Set("Content-Type", "application/json")
			writeHTTPTestString(t, writer, "{ \"n\" : 1 }\n")
			return
		}
		writeHTTPTestBytes(t, writer, body)
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	require.NoError(t, err)
	assert.Equal(t, string(body), stdout, "default raw response body")

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--select", "body", "--format", "raw")
	require.NoError(t, err)
	assert.Equal(t, string(body), stdout, "explicit raw response body")

	stdout, _, err = executeRootStreams(t, "http", server.URL+"/application-json", "--select", "body", "--format", "raw")
	require.NoError(t, err)
	assert.Equal(t, "{ \"n\" : 1 }\n", stdout, "application JSON bytes are unchanged")

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--select", "body", "--format", "json")
	require.NoError(t, err)
	var bodyReport map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(stdout), &bodyReport))
	assert.ElementsMatch(t, []string{"body", "body_encoding", "complete"}, mapKeys(bodyReport))
	var encodedBody string
	require.NoError(t, json.Unmarshal(bodyReport["body"], &encodedBody))
	assert.Equal(t, base64.StdEncoding.EncodeToString(body), encodedBody)
	assert.JSONEq(t, `"base64"`, string(bodyReport["body_encoding"]))
	assert.JSONEq(t, `true`, string(bodyReport["complete"]))

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--select", "response", "--format", "json")
	require.NoError(t, err)
	envelope := decodeHTTPEnvelope(t, stdout)
	assert.Equal(t, http.StatusOK, envelope.StatusCode)
	assert.Equal(t, []string{"selected"}, envelope.Headers["X-Npc-Test"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(body), envelope.Body)
	assert.True(t, envelope.Complete)
}

func TestExampleHTTPResponseSelectionAndEncoding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-NPC-Test", "selected")
		writeHTTPTestString(t, writer, "body\n")
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--select", "response")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stdout, "HTTP/1.1 200 OK\n"), "response status: %q", stdout)
	assert.Contains(t, stdout, "X-Npc-Test: selected\n")
	assert.True(t, strings.HasSuffix(stdout, "\n\nbody\n"), "response separator and body: %q", stdout)

	encoded, _, err := executeRootStreams(t, "http", server.URL, "--select", "response", "--encoding", "base64")
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err, "decode whole response output")
	assert.True(t, strings.HasPrefix(string(decoded), "HTTP/1.1 200 OK\n"))
	assert.Contains(t, string(decoded), "X-Npc-Test: selected\n")
	assert.True(t, strings.HasSuffix(string(decoded), "\n\nbody\n"))

	encoded, _, err = executeRootStreams(t, "http", server.URL, "--select", "body", "--format", "json", "-e", "base64")
	require.NoError(t, err)
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err, "decode whole JSON output")
	var report map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(decoded, &report))
	assert.JSONEq(t, `"Ym9keQo="`, string(report["body"]))

	encoded, _, err = executeRootStreams(t, "http", server.URL, "--select", "response", "--format", "json", "-e", "base64")
	require.NoError(t, err)
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err, "decode whole response JSON output")
	envelope := decodeHTTPEnvelope(t, string(decoded))
	assert.Equal(t, http.StatusOK, envelope.StatusCode)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("body\n")), envelope.Body)
}

func TestExampleHTTPHeadOutputSelection(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("method = %q, want HEAD", request.Method)
		}
		writer.Header().Set("X-NPC-Test", "head")
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "-X", "HEAD")
	require.NoError(t, err)
	assert.Empty(t, stdout, "default HEAD body selection")

	stdout, _, err = executeRootStreams(t, "http", server.URL, "-X", "HEAD", "--select", "response")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stdout, "HTTP/1.1 204 No Content\n"), "HEAD status: %q", stdout)
	assert.Contains(t, stdout, "X-Npc-Test: head\n")
	assert.True(t, strings.HasSuffix(stdout, "\n\n"), "HEAD header separator: %q", stdout)
}

func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
