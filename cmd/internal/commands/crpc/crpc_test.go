package crpc_test

import (
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRPCNegotiatesHTTPSWithHTTP1Fallback(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2.0"} {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			server := echoServer(t, true, protocol == "HTTP/2.0")
			ca := filepath.Join(t.TempDir(), "ca.pem")
			require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			require.NoError(t, err)
			// A different dial address must retain URL identity for certificate verification.
			host := net.JoinHostPort("127.0.0.2", port)
			output, diagnostics, err := run(t, nil, "crpc", host+echoMethod,
				"--resolve", host+":127.0.0.1", "--servername", "example.com", "--ca", ca, "-d", `{}`, "-v")
			require.NoError(t, err)
			assert.JSONEq(t, `{}`, output)
			assert.Contains(t, diagnostics, "Connect transport: "+protocol)
			assert.Contains(t, diagnostics, "verified=true")
		})
	}
}

func TestCRPCPreservesRoutingAndEncodedIO(t *testing.T) {
	t.Parallel()
	seen := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		seen <- request.RequestURI
		assert.Equal(t, "application/json", request.Header.Get("Content-Type"))
		assert.Equal(t, "1", request.Header.Get("Connect-Protocol-Version"))
		assert.Equal(t, "Bearer example", request.Header.Get("Authorization"))
		output.Header().Set("Content-Type", "application/json")
		_, err := io.Copy(output, request.Body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	const message = `{"count":9007199254740993}`
	input := filepath.Join(t.TempDir(), "request.b64")
	require.NoError(t, os.WriteFile(input, []byte(base64.StdEncoding.EncodeToString([]byte(message))), 0o600))
	for _, target := range [][]string{{server.URL + "/tenant%2Fone" + echoMethod}, {server.URL + "/tenant%2Fone/", strings.TrimPrefix(echoMethod, "/")}} {
		args := append([]string{"crpc"}, target...)
		args = append(args, "-i", input, "--input-encoding", "base64", "-e", "base64", "-H", "Authorization: Bearer example")
		output, _, err := run(t, nil, args...)
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(output)
		require.NoError(t, err)
		assert.Equal(t, message+"\n", string(decoded))
		assert.Equal(t, "/tenant%2Fone"+echoMethod, <-seen)
	}
}

func TestCRPCRejectsInvalidRequestBeforeIO(t *testing.T) {
	t.Parallel()
	for _, flags := range [][]string{
		{"-d", "{}", "-i", "-"},
		{"--stdin", "sometimes"},
		{"-d", "{}", "--stdin", "always"},
		{"--timeout", "-1s"},
		{"--connect-timeout", "-1s"},
		{"--max-message-size", "0"},
		{"--format", "text"},
		{"--ca", "missing"},
		{"-k", "missing"},
		{"--resolve", "invalid"},
		{"-H", "bad header: value"},
		{"-H", "content-type: text/html"},
		{"-H", "Connect-Protocol-Version: 2"},
		{"-H", "X-Value: a\nb"},
		{"-d", ""},
		{"-d", "{} {}"},
		{"-d", `{"a":1,"a":2}`},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, os.WriteFile(output, []byte("existing"), 0o600))
			input := &unexpectedInput{t: t}
			args := append([]string{"crpc", "http://127.0.0.1:1" + echoMethod, "-o", output}, flags...)
			_, _, err := run(t, input, args...)
			require.Error(t, err)
			contents, err := os.ReadFile(output)
			require.NoError(t, err)
			assert.Equal(t, "existing", string(contents))
		})
	}
}

func TestCRPCFailurePreservesOutputAndDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var followed atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	t.Cleanup(destination.Close)
	for _, response := range []struct {
		name, contentType, body string
		status                  int
	}{
		{"redirect", "text/plain", "moved", http.StatusTemporaryRedirect},
		{"RPC failure", "application/json", `{"code":"invalid_argument","message":"bad\nConnect transport: forged"}`, http.StatusBadRequest},
		{"HTML proxy", "text/html", "<html>not an RPC server</html>", http.StatusOK},
		{"malformed JSON", "application/json", "{} {}", http.StatusOK},
	} {
		t.Run(response.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, _ *http.Request) {
				output.Header().Set("Content-Type", response.contentType)
				output.Header().Set("Location", destination.URL)
				output.WriteHeader(response.status)
				_, err := io.WriteString(output, response.body)
				assert.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			path := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(path, []byte("existing"), 0o600))
			_, diagnostics, err := run(t, nil, "crpc", server.URL+echoMethod, "-d", "{}", "-o", path, "-v")
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "\nConnect transport: forged")
			assert.NotContains(t, diagnostics, "\nConnect transport: forged")
			assert.False(t, followed.Load())
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "existing", string(data))
		})
	}
}

func TestCRPCMessageSizeBoundaries(t *testing.T) {
	t.Parallel()
	const limit = 32
	for _, size := range []int{limit - 1, limit, limit + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			message := `"` + strings.Repeat("x", size-2) + `"`
			server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, _ *http.Request) {
				output.Header().Set("Content-Type", "application/json")
				_, err := io.WriteString(output, message)
				assert.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			for _, input := range []string{`{}`, message} {
				output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "-d", input, "--max-message-size", "32")
				if size > limit {
					require.Error(t, err)
					assert.Empty(t, output)
				} else {
					require.NoError(t, err)
					assert.Equal(t, message+"\n", output)
				}
			}
		})
	}
}

type unexpectedInput struct{ t *testing.T }

func (input *unexpectedInput) Read([]byte) (int, error) {
	input.t.Error("invalid options consumed input")
	return 0, io.EOF
}
