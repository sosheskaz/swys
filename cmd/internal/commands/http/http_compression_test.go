package http_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPAutomaticResponseCompression(t *testing.T) {
	t.Parallel()

	payload := []byte("response compressed by the server\n")
	compressed := encodeHTTPGzipTestBody(t, payload)
	for _, protocol := range []int{1, 2} {
		t.Run(fmt.Sprintf("HTTP%d", protocol), func(t *testing.T) {
			t.Parallel()
			received := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				received <- request.Header.Get("Accept-Encoding")
				writer.Header().Set("Content-Encoding", "gzip")
				writer.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
				if _, err := writer.Write(compressed); err != nil {
					t.Errorf("write compressed response: %v", err)
				}
			}))
			server.EnableHTTP2 = protocol == 2
			server.StartTLS()
			t.Cleanup(server.Close)

			stdout, _, err := executeRootStreams(t, "http", server.URL, "--insecure")
			if err != nil {
				t.Fatalf("HTTP gzip response: %v", err)
			}
			require.Equal(t, string(payload), stdout)
			if got := <-received; got != "gzip" {
				t.Fatalf("Accept-Encoding = %q, want gzip", got)
			}
		})
	}
}

func TestHTTPAutomaticCompressionUpdatesResponseMetadata(t *testing.T) {
	t.Parallel()

	payload := []byte("decoded metadata body")
	compressed := encodeHTTPGzipTestBody(t, payload)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	included, _, err := executeRootStreams(t, "http", server.URL, "--select", "response")
	require.NoError(t, err)
	if strings.Contains(strings.ToLower(included), "content-encoding:") || strings.Contains(strings.ToLower(included), "content-length:") {
		t.Fatalf("included response retained encoded metadata: %q", included)
	}
	if !strings.HasSuffix(included, string(payload)) {
		t.Fatalf("included response = %q, want decoded body", included)
	}

	jsonOutput, _, err := executeRootStreams(t, "http", server.URL, "--select", "response", "--format", "json")
	require.NoError(t, err)
	envelope := decodeHTTPEnvelope(t, jsonOutput)
	if _, exists := envelope.Headers["Content-Encoding"]; exists {
		t.Fatalf("JSON headers retained Content-Encoding: %#v", envelope.Headers)
	}
	if _, exists := envelope.Headers["Content-Length"]; exists {
		t.Fatalf("JSON headers retained Content-Length: %#v", envelope.Headers)
	}
	if envelope.Body != base64.StdEncoding.EncodeToString(payload) || !envelope.Complete {
		t.Fatalf("JSON envelope = %+v", envelope)
	}
}

func TestHTTPAutomaticCompressionFollowsRedirects(t *testing.T) {
	t.Parallel()

	payload := []byte("redirected and decoded")
	compressed := encodeHTTPGzipTestBody(t, payload)
	received := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Get("Accept-Encoding")
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/final", http.StatusFound)
			return
		}
		writer.Header().Set("Content-Encoding", "gzip")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL+"/start")
	require.NoError(t, err)
	require.Equal(t, string(payload), stdout)
	if got := []string{<-received, <-received}; !slices.Equal(got, []string{"gzip", "gzip"}) {
		t.Fatalf("redirect Accept-Encoding values = %q", got)
	}
}

func TestHTTPExplicitAcceptEncodingPreservesResponse(t *testing.T) {
	t.Parallel()

	compressed := encodeHTTPGzipTestBody(t, []byte("explicitly compressed"))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "gzip" {
			t.Errorf("Accept-Encoding = %q, want gzip", got)
		}
		writer.Header().Set("Content-Encoding", "gzip")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "-H", "Accept-Encoding: gzip")
	require.NoError(t, err)
	require.Equal(t, string(compressed), stdout)
}

func TestHTTPAutomaticCompressionSkipsIneligibleRequests(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "explicit empty", args: []string{"-H", "Accept-Encoding:"}, want: []string{""}},
		{name: "range", args: []string{"-H", "Range: bytes=0-3"}},
		{name: "head", args: []string{"-X", "HEAD"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			received := make(chan []string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				received <- request.Header.Values("Accept-Encoding")
				writer.Header().Set("X-NPC-Test", "compression")
				if request.Method != http.MethodHead {
					writeHTTPTestString(t, writer, "raw")
				}
			}))
			t.Cleanup(server.Close)

			args := append([]string{"http"}, test.args...)
			args = append(args, server.URL)
			if _, _, err := executeRootStreams(t, args...); err != nil {
				t.Fatal(err)
			}
			if got := <-received; !slices.Equal(got, test.want) {
				t.Fatalf("Accept-Encoding = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHTTPAutomaticCompressionPreservesUnsupportedEncoding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "zstd")
		writeHTTPTestString(t, writer, "opaque")
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--select", "response")
	require.NoError(t, err)
	if !strings.Contains(stdout, "Content-Encoding: zstd") || !strings.HasSuffix(stdout, "opaque") {
		t.Fatalf("response = %q, want untouched unsupported encoding", stdout)
	}
}

func TestHTTPAutomaticCompressionReportsMalformedGzip(t *testing.T) {
	t.Parallel()

	compressed := encodeHTTPGzipTestBody(t, []byte("truncated compressed body"))
	compressed = compressed[:len(compressed)/2]
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write malformed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--select", "response", "--format", "json")
	require.Error(t, err)
	envelope := decodeHTTPEnvelope(t, stdout)
	if envelope.Complete || envelope.Error == "" {
		t.Fatalf("envelope = %+v, want gzip decoding error", envelope)
	}
}

func TestHTTPAutomaticCompressionIgnoresBodylessResponseEncoding(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNoContent, http.StatusResetContent, http.StatusNotModified} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", "gzip")
				writer.WriteHeader(status)
			}))
			t.Cleanup(server.Close)
			stdout, _, err := executeRootStreams(t, "http", server.URL)
			require.NoError(t, err)
			require.Empty(t, stdout)
		})
	}
}

func encodeHTTPGzipTestBody(tb testing.TB, payload []byte) []byte {
	tb.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(payload); err != nil {
		tb.Fatalf("encode gzip test body: %v", err)
	}
	if err := writer.Close(); err != nil {
		tb.Fatalf("close gzip test encoder: %v", err)
	}
	return output.Bytes()
}
