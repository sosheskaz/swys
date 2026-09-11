package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestHTTPAutomaticResponseCompression(t *testing.T) {
	t.Parallel()

	payload := []byte("response compressed by the server\n")
	for _, protocol := range []int{1, 2} {
		for _, coding := range []string{"gzip", "br", "zstd"} {
			t.Run(fmt.Sprintf("HTTP%d/%s", protocol, coding), func(t *testing.T) {
				t.Parallel()
				compressed := encodeHTTPTestBody(t, payload, coding)
				received := make(chan string, 1)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					received <- request.Header.Get("Accept-Encoding")
					writer.Header().Set("Content-Encoding", coding)
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
					t.Fatalf("HTTP %s response: %v", coding, err)
				}
				if stdout != string(payload) {
					t.Fatalf("stdout = %q, want %q", stdout, payload)
				}
				if got := <-received; got != "gzip, br, zstd" {
					t.Fatalf("Accept-Encoding = %q", got)
				}
			})
		}
	}
}

func TestHTTPAutomaticCompressionUpdatesResponseMetadata(t *testing.T) {
	t.Parallel()

	payload := []byte("decoded metadata body")
	compressed := encodeHTTPTestBody(t, payload, "zstd")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "zstd")
		writer.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	included, _, err := executeRootStreams(t, "http", server.URL, "--include")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(included), "content-encoding:") || strings.Contains(strings.ToLower(included), "content-length:") {
		t.Fatalf("included response retained encoded metadata: %q", included)
	}
	if !strings.HasSuffix(included, string(payload)) {
		t.Fatalf("included response = %q, want decoded body", included)
	}

	jsonOutput, _, err := executeRootStreams(t, "http", server.URL, "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
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

	encoded, _, err := executeRootStreams(t, "http", server.URL, "--encoding", "base64")
	if err != nil {
		t.Fatal(err)
	}
	if encoded != base64.StdEncoding.EncodeToString(payload) {
		t.Fatalf("encoded body = %q, want base64 decoded response", encoded)
	}
}

func TestHTTPAutomaticCompressionFollowsRedirects(t *testing.T) {
	t.Parallel()

	payload := []byte("redirected and decoded")
	compressed := encodeHTTPTestBody(t, payload, "br")
	received := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Get("Accept-Encoding")
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/final", http.StatusFound)
			return
		}
		writer.Header().Set("Content-Encoding", "br")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(payload) {
		t.Fatalf("stdout = %q, want %q", stdout, payload)
	}
	if got := []string{<-received, <-received}; !slices.Equal(got, []string{"gzip, br, zstd", "gzip, br, zstd"}) {
		t.Fatalf("redirect Accept-Encoding values = %q", got)
	}
}

func TestHTTPExplicitAcceptEncodingPreservesResponse(t *testing.T) {
	t.Parallel()

	payload := []byte("explicitly compressed")
	compressed := encodeHTTPTestBody(t, payload, "br")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "br" {
			t.Errorf("Accept-Encoding = %q, want br", got)
		}
		writer.Header().Set("Content-Encoding", "br")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "-H", "Accept-Encoding: br")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(compressed) {
		t.Fatalf("stdout bytes = %x, want raw compressed bytes %x", stdout, compressed)
	}
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

func TestHTTPAutomaticCompressionContentEncodingChains(t *testing.T) {
	t.Parallel()

	payload := []byte("multiply encoded")
	compressed := encodeHTTPTestBody(t, payload, "gzip", "br")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip, br")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write compressed response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(payload) {
		t.Fatalf("stdout = %q, want %q", stdout, payload)
	}
}

func TestHTTPAutomaticCompressionPreservesUnknownContentEncoding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "deflate")
		writeHTTPTestString(t, writer, "opaque")
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--include")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Content-Encoding: deflate") || !strings.HasSuffix(stdout, "opaque") {
		t.Fatalf("response = %q, want untouched unknown encoding", stdout)
	}
}

func TestHTTPAutomaticCompressionReportsMalformedBodies(t *testing.T) {
	t.Parallel()

	for _, coding := range []string{"gzip", "br", "zstd"} {
		t.Run(coding, func(t *testing.T) {
			t.Parallel()
			compressed := encodeHTTPTestBody(t, []byte("truncated compressed body"), coding)
			compressed = compressed[:len(compressed)/2]
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", coding)
				if _, err := writer.Write(compressed); err != nil {
					t.Errorf("write malformed response: %v", err)
				}
			}))
			t.Cleanup(server.Close)

			stdout, _, err := executeRootStreams(t, "http", server.URL, "--format", "json")
			if err == nil {
				t.Fatal("malformed compressed response succeeded")
			}
			envelope := decodeHTTPEnvelope(t, stdout)
			if envelope.Complete || !strings.Contains(envelope.Error, coding) {
				t.Fatalf("envelope = %+v, want %s decoding error", envelope, coding)
			}
		})
	}
}

func TestHTTPAutomaticCompressionAllowsLargeStreamingBody(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("streamed zstd response\n"), (9<<20)/23+1)
	compressed := encodeHTTPZstdTestBody(t, payload, 1<<20)
	body := &httpDecodedBody{source: io.NopCloser(bytes.NewReader(compressed)), codings: []string{"zstd"}}
	count, err := io.Copy(io.Discard, body)
	if err != nil {
		t.Fatalf("decode body larger than window limit: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if count != int64(len(payload)) {
		t.Fatalf("decoded %d bytes, want %d", count, len(payload))
	}
}

func TestHTTPAutomaticCompressionRejectsOversizedZstdWindow(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("oversized zstd window\n"), (9<<20)/22+1)
	compressed := encodeHTTPZstdTestBody(t, payload, 16<<20)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "zstd")
		if _, err := writer.Write(compressed); err != nil {
			t.Errorf("write oversized-window response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--format", "json")
	if err == nil {
		t.Fatal("oversized zstd window succeeded")
	}
	envelope := decodeHTTPEnvelope(t, stdout)
	if envelope.Complete || !strings.Contains(envelope.Error, "zstd") {
		t.Fatalf("envelope = %+v, want zstd window error", envelope)
	}
}

func TestHTTPAutomaticCompressionIgnoresBodylessResponseEncoding(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNoContent, http.StatusResetContent, http.StatusNotModified} {
		for _, coding := range []string{"gzip", "br", "zstd"} {
			t.Run(strconv.Itoa(status)+"/"+coding, func(t *testing.T) {
				t.Parallel()
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Encoding", coding)
					writer.WriteHeader(status)
				}))
				t.Cleanup(server.Close)
				stdout, _, err := executeRootStreams(t, "http", server.URL)
				if err != nil {
					t.Fatal(err)
				}
				if stdout != "" {
					t.Fatalf("stdout = %q, want empty body", stdout)
				}
			})
		}
	}
}

func encodeHTTPTestBody(tb testing.TB, payload []byte, codings ...string) []byte {
	tb.Helper()
	encoded := append([]byte(nil), payload...)
	for _, coding := range codings {
		var output bytes.Buffer
		var writer io.WriteCloser
		switch coding {
		case "gzip":
			writer = gzip.NewWriter(&output)
		case "br":
			writer = brotli.NewWriter(&output)
		case "zstd":
			var err error
			writer, err = zstd.NewWriter(&output, zstd.WithEncoderConcurrency(1))
			if err != nil {
				tb.Fatalf("create zstd test encoder: %v", err)
			}
		default:
			tb.Fatalf("unsupported test coding %q", coding)
		}
		if _, err := writer.Write(encoded); err != nil {
			tb.Fatalf("encode %s test body: %v", coding, err)
		}
		if err := writer.Close(); err != nil {
			tb.Fatalf("close %s test encoder: %v", coding, err)
		}
		encoded = output.Bytes()
	}
	return encoded
}

func encodeHTTPZstdTestBody(tb testing.TB, payload []byte, window int) []byte {
	tb.Helper()
	var output bytes.Buffer
	writer, err := zstd.NewWriter(
		&output,
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(window),
		zstd.WithSingleSegment(false),
	)
	if err != nil {
		tb.Fatalf("create zstd test encoder: %v", err)
	}
	if _, err := writer.Write(payload); err != nil {
		tb.Fatalf("encode zstd test body: %v", err)
	}
	if err := writer.Close(); err != nil {
		tb.Fatalf("close zstd test encoder: %v", err)
	}
	return output.Bytes()
}
