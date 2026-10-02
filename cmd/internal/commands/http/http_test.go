package http_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/version"
)

var (
	errHTTPTestInputClosed  = errors.New("HTTP test input closed")
	errHTTPTestOutputFailed = errors.New("HTTP test output failed")
)

func TestHTTPMethodRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		methodArg  string
		wantMethod string
	}{
		{name: "get", methodArg: "GET", wantMethod: http.MethodGet},
		{name: "lowercase custom method", methodArg: "get", wantMethod: "get"},
		{name: "post", methodArg: "POST", wantMethod: http.MethodPost},
		{name: "head", methodArg: "HEAD", wantMethod: http.MethodHead},
		{name: "put", methodArg: "PUT", wantMethod: http.MethodPut},
		{name: "patch", methodArg: "PATCH", wantMethod: http.MethodPatch},
		{name: "delete", methodArg: "DELETE", wantMethod: http.MethodDelete},
		{name: "options", methodArg: "OPTIONS", wantMethod: http.MethodOptions},
		{name: "custom method preserves case", methodArg: "ProPFIND", wantMethod: "ProPFIND"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gotMethod := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				gotMethod <- request.Method
				if request.Method == http.MethodHead {
					writer.Header().Set("X-HTTP-Test", "head")
					writer.WriteHeader(http.StatusNoContent)
					return
				}
				writeHTTPTestString(t, writer, "ok")
			}))
			t.Cleanup(server.Close)

			stdout, _, err := executeRootStreams(t, "http", server.URL, "--method", test.methodArg, "--stdin", "never")
			require.NoError(t, err, "http %s", test.methodArg)
			require.Equal(t, test.wantMethod, <-gotMethod, "request method")
			if test.wantMethod == http.MethodHead {
				assert.Empty(t, stdout, "default HEAD body")
			} else {
				assert.Equal(t, "ok", stdout, "response body")
			}
		})
	}
}

func TestBareHTTPShowsHelpWithoutOpeningIO(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "existing-output")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	input := &countingReader{source: strings.NewReader("must not be read")}
	stdout, _, err := executeHTTPStreamsWithInput(t, input, "http", "--output", outputPath)
	require.NoError(t, err, "bare HTTP command: %v", err)
	assert.Contains(t, stdout, "Make an HTTP request")
	assert.Zero(t, input.reads.Load(), "bare HTTP command read stdin")
	contents, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(contents), "existing output")
}

func TestHTTPRejectsInvalidMethodArgumentsBeforeIO(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"-X", "BAD METHOD"},
		{"--method", ""},
		{"POST"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var called atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called.Store(true)
			}))
			t.Cleanup(server.Close)
			outputPath := filepath.Join(t.TempDir(), "response")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			input := &countingReader{source: strings.NewReader("unread")}
			commandArgs := append([]string{"http", server.URL, "--output", outputPath}, args...)
			_, _, err := executeHTTPStreamsWithInput(t, input, commandArgs...)
			require.Error(t, err, "invalid method arguments succeeded")
			require.False(t, called.Load() || input.reads.Load() != 0, "invalid method arguments performed I/O")
			contents, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(contents), "existing output")
		})
	}
}

func TestHTTPMethodCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, flag, prefix string
		want               []string
	}{
		{name: "long flag P prefix", flag: "--method", prefix: "P", want: []string{"POST", "PUT", "PATCH"}},
		{name: "long flag QUERY", flag: "--method", prefix: "Q", want: []string{"QUERY"}},
		{name: "short flag QUERY", flag: "-X", prefix: "Q", want: []string{"QUERY"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "__complete", "http", test.flag, test.prefix)
			require.NoError(t, err)
			for _, method := range test.want {
				assert.Contains(t, stdout, method+"\n")
			}
		})
	}
}

func TestHTTPRequestBodySources(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	rawPath := filepath.Join(directory, "request.bin")
	jsonPath := filepath.Join(directory, "request.json")
	require.NoError(t, os.WriteFile(rawPath, []byte("file bytes"), 0o600))
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"source":"file"}`), 0o600))

	tests := []struct {
		name            string
		stdin           string
		wantBody        string
		wantContentType string
		args            []string
	}{
		{name: "literal data", args: []string{"--data", "literal bytes"}, wantBody: "literal bytes"},
		{name: "input file", args: []string{"--input", rawPath}, wantBody: "file bytes"},
		{name: "input stdin", args: []string{"--input", "-"}, stdin: "stdin bytes", wantBody: "stdin bytes"},
		{name: "literal json", args: []string{"--json", `{"source":"literal"}`}, wantBody: `{"source":"literal"}`, wantContentType: "application/json"},
		{name: "json file", args: []string{"--json", "@" + jsonPath}, wantBody: `{"source":"file"}`, wantContentType: "application/json"},
		{name: "json stdin", args: []string{"--json", "@-"}, stdin: `{"source":"stdin"}`, wantBody: `{"source":"stdin"}`, wantContentType: "application/json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			type requestRecord struct {
				body        string
				contentType string
			}
			received := make(chan requestRecord, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, readErr := io.ReadAll(request.Body)
				received <- requestRecord{body: string(body), contentType: request.Header.Get("Content-Type")}
				if readErr != nil {
					http.Error(writer, readErr.Error(), http.StatusInternalServerError)
					return
				}
				writeHTTPTestString(t, writer, "received")
			}))
			t.Cleanup(server.Close)

			args := append([]string{"http", "-X", "POST", server.URL}, test.args...)
			stdout, stderr, err := executeHTTPStreamsWithInput(t, strings.NewReader(test.stdin), args...)
			require.NoError(t, err, "HTTP request")
			require.Empty(t, stderr, "request diagnostics")
			require.Equal(t, "received", stdout, "response body")
			record := <-received
			assert.Equal(t, test.wantBody, record.body, "request body")
			assert.Equal(t, test.wantContentType, record.contentType, "Content-Type")
		})
	}
}

func TestHTTPInputEncodingDecodesRawBody(t *testing.T) {
	t.Parallel()

	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read encoded request body: %v", err)
			return
		}
		received <- string(body)
		writeHTTPTestString(t, writer, "ok")
	}))
	t.Cleanup(server.Close)

	_, _, err := executeHTTPStreamsWithInput(
		t,
		strings.NewReader(base64.StdEncoding.EncodeToString([]byte("decoded bytes"))),
		"http", "-X", "POST", server.URL, "--input", "-", "--input-encoding", "base64",
	)
	require.NoError(t, err, "HTTP encoded input: %v", err)
	assert.Equal(t, "decoded bytes", <-received, "decoded request body")
}

func TestHTTPFormAndMultipartBodies(t *testing.T) {
	t.Parallel()

	t.Run("URL encoded fields", func(t *testing.T) {
		t.Parallel()

		type formRecord struct {
			contentType string
			values      []string
		}
		received := make(chan formRecord, 1)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse form request: %v", err)
				return
			}
			received <- formRecord{contentType: request.Header.Get("Content-Type"), values: request.Form["name"]}
			writeHTTPTestString(t, writer, "ok")
		}))
		t.Cleanup(server.Close)

		_, _, err := executeRootStreams(
			t,
			"http", "-X", "POST", server.URL,
			"--form", "name=first", "--form", "name=second",
		)
		require.NoError(t, err, "HTTP form request")
		record := <-received
		assert.Equal(t, "application/x-www-form-urlencoded", record.contentType, "form Content-Type")
		assert.Equal(t, []string{"first", "second"}, record.values, "repeated form values")
	})

	t.Run("multipart file and field", func(t *testing.T) {
		t.Parallel()

		uploadPath := filepath.Join(t.TempDir(), "report.txt")
		require.NoError(t, os.WriteFile(uploadPath, []byte("report contents"), 0o600))
		type multipartRecord struct {
			err      error
			field    string
			filename string
			file     string
		}
		received := make(chan multipartRecord, 1)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			record := multipartRecord{}
			if err := request.ParseMultipartForm(1 << 20); err != nil {
				record.err = err
			} else {
				record.field = request.FormValue("name")
				file, header, err := request.FormFile("attachment")
				if err != nil {
					record.err = err
				} else {
					record.filename = header.Filename
					contents, readErr := io.ReadAll(file)
					record.file = string(contents)
					record.err = errors.Join(readErr, file.Close())
				}
			}
			received <- record
			writeHTTPTestString(t, writer, "ok")
		}))
		t.Cleanup(server.Close)

		_, _, err := executeRootStreams(
			t,
			"http", "-X", "POST", server.URL,
			"--form", "name=demo", "--file", "attachment="+uploadPath,
		)
		require.NoError(t, err, "HTTP multipart request")
		record := <-received
		require.NoError(t, record.err, "parse multipart request")
		assert.Equal(t, "demo", record.field, "multipart field")
		assert.Equal(t, "report.txt", record.filename, "multipart filename")
		assert.Equal(t, "report contents", record.file, "multipart file")
	})
}

func TestHTTPHeaders(t *testing.T) {
	t.Parallel()

	received := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Values("X-NPC-Test")
		writeHTTPTestString(t, writer, "ok")
	}))
	t.Cleanup(server.Close)

	_, _, err := executeRootStreams(
		t,
		"http", server.URL,
		"-H", "X-NPC-Test: first", "--header", "X-NPC-Test: second",
	)
	require.NoError(t, err, "HTTP headers: %v", err)
	assert.Equal(t, []string{"first", "second"}, <-received, "repeated header values")
}

func TestHTTPUserAgent(t *testing.T) {
	t.Parallel()
	buildVersion := version.Get().Version
	if buildVersion == "" || buildVersion == "(devel)" {
		buildVersion = "dev"
	}
	for _, protocol := range []int{1, 2} {
		for _, test := range []struct {
			name   string
			header string
			want   []string
		}{
			{name: "default", want: []string{"npc/" + buildVersion}},
			{name: "override", header: "user-agent: custom/1.0", want: []string{"custom/1.0"}},
			{name: "suppressed", header: "User-Agent:"},
		} {
			t.Run(fmt.Sprintf("HTTP%d/%s", protocol, test.name), func(t *testing.T) {
				t.Parallel()
				type receivedRequest struct {
					values   []string
					protocol int
				}
				received := make(chan receivedRequest, 2)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					received <- receivedRequest{values: request.Header.Values("User-Agent"), protocol: request.ProtoMajor}
					if request.URL.Path == "/" {
						http.Redirect(writer, request, "/final", http.StatusFound)
						return
					}
					writeHTTPTestString(t, writer, "ok")
				}))
				server.EnableHTTP2 = protocol == 2
				server.StartTLS()
				t.Cleanup(server.Close)
				args := []string{"http", server.URL, "--insecure"}
				if test.header != "" {
					args = append(args, "-H", test.header)
				}
				_, _, err := executeRootStreams(t, args...)
				require.NoError(t, err)
				for range 2 {
					got := <-received
					if got.protocol != protocol || !slices.Equal(got.values, test.want) {
						t.Fatalf("received HTTP%d User-Agent %q, want HTTP%d %q", got.protocol, got.values, protocol, test.want)
					}
				}
			})
		}
	}
}

func TestHTTPStdinPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		stdin    string
		flag     string
		wantBody string
		wantRead bool
	}{
		{name: "auto post", method: "POST", stdin: "automatic", wantBody: "automatic", wantRead: true},
		{name: "auto get", method: "GET", stdin: "ignored", wantBody: "", wantRead: false},
		{name: "never post", method: "POST", stdin: "ignored", flag: "never", wantBody: "", wantRead: false},
		{name: "always get", method: "GET", stdin: "explicit", flag: "always", wantBody: "explicit", wantRead: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			received := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Errorf("read stdin request body: %v", err)
					return
				}
				received <- string(body)
				writeHTTPTestString(t, writer, "ok")
			}))
			t.Cleanup(server.Close)

			input := &countingReader{source: strings.NewReader(test.stdin)}
			args := []string{"http", "-X", test.method, server.URL}
			if test.flag != "" {
				args = append(args, "--stdin", test.flag)
			}
			_, _, err := executeHTTPStreamsWithInput(t, input, args...)
			require.NoError(t, err, "HTTP stdin policy")
			assert.Equal(t, test.wantBody, <-received, "request body")
			assert.Equal(t, test.wantRead, input.reads.Load() > 0, "stdin read")
		})
	}
}

func TestHTTPBodyValidationHappensBeforeOutputIsOpened(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "GET shorthand body", args: []string{"--data", "body"}},
		{name: "conflicting raw and JSON", args: []string{"-X", "POST", "--data", "body", "--json", `{}`}},
		{name: "conflicting JSON and form", args: []string{"-X", "POST", "--json", `{}`, "--form", "name=value"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var called atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called.Store(true)
			}))
			t.Cleanup(server.Close)
			outputPath := filepath.Join(t.TempDir(), "existing-output")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))

			args := append([]string{"http", server.URL}, test.args...)
			args = append(args, "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			require.Error(t, err, "invalid body selection succeeded")
			require.False(t, called.Load(), "server received request before body validation")
			contents, readErr := os.ReadFile(outputPath)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(contents), "existing output")
		})
	}
}

func TestHTTPFileSourcesCannotBeTheirOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		flag func(string) []string
		name string
	}{
		{name: "raw input", flag: func(path string) []string { return []string{"--input", path} }},
		{name: "JSON file", flag: func(path string) []string { return []string{"--json", "@" + path} }},
		{name: "multipart upload", flag: func(path string) []string { return []string{"--file", "attachment=" + path} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "source.txt")
			require.NoError(t, os.WriteFile(path, []byte("preserve source"), 0o600))
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(server.Close)

			args := append([]string{"http", "-X", "POST", server.URL}, test.flag(path)...)
			args = append(args, "--output", path)
			_, _, err := executeRootStreams(t, args...)
			require.Error(t, err, "source/output collision succeeded")
			contents, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve source", string(contents), "source after collision")
		})
	}
}

func TestHTTPJSONResponseEnvelopeAndTrace(t *testing.T) {
	t.Parallel()

	responseBody := []byte{0x00, 0xff, '\n'}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Add("X-NPC-Test", "first")
		writer.Header().Add("X-NPC-Test", "second")
		writeHTTPTestBytes(t, writer, responseBody)
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", "-X", "GET", server.URL, "--select", "response", "--format", "json", "--trace")
	require.NoError(t, err, "HTTP JSON response: %v", err)
	assert.Contains(t, stderr, "http trace 1:", "trace diagnostics")
	envelope := decodeHTTPEnvelope(t, stdout)
	assert.Equal(t, http.MethodGet, envelope.Method, "request method")
	assert.Equal(t, server.URL, envelope.URL, "request URL")
	assert.Equal(t, http.StatusOK, envelope.StatusCode, "response status code")
	assert.Equal(t, "200 OK", envelope.Status, "response status")
	if !strings.HasPrefix(envelope.Protocol, "HTTP/") {
		t.Fatalf("protocol = %q, want HTTP version", envelope.Protocol)
	}
	assert.Equal(t, []string{"first", "second"}, envelope.Headers["X-Npc-Test"], "response headers")
	assert.Equal(t, "base64", envelope.BodyEncoding, "body encoding")
	assert.Equal(t, base64.StdEncoding.EncodeToString(responseBody), envelope.Body, "response body")
	assert.True(t, envelope.Complete, "response completion")
	assert.Empty(t, envelope.Error, "response error")
	assert.Empty(t, envelope.Trace, "trace must not enter JSON output")
}

func TestHTTPTextTraceIsWrittenToStderr(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "body")
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL, "--trace")
	require.NoError(t, err, "HTTP text trace: %v", err)
	assert.Equal(t, "body", stdout)
	assert.NotEmpty(t, strings.TrimSpace(stderr), "trace diagnostics")
}

func TestHTTPResponseSelectionAndOutputEncoding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-NPC-Test", "included")
		writeHTTPTestString(t, writer, "abc")
	}))
	t.Cleanup(server.Close)

	t.Run("select response status and headers", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := executeRootStreams(t, "http", server.URL, "--select", "response")
		require.NoError(t, err, "HTTP response selection")
		assert.Contains(t, stdout, "200 OK", "included status")
		assert.Contains(t, stdout, "X-Npc-Test: included", "included header")
		assert.True(t, strings.HasSuffix(stdout, "abc"), "included body: %q", stdout)
	})

	t.Run("encode body only", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := executeRootStreams(t, "http", server.URL, "--encoding", "base64")
		require.NoError(t, err, "HTTP encoded response")
		assert.Equal(t, "YWJj", stdout, "base64 body")
	})
}

func TestHTTPRejectsIncompatibleSelectionAndFormatBeforeOutput(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"--select", "body", "--format", "text"},
		{"--select", "response", "--format", "raw"},
		{"--format", ""},
	}
	for _, flags := range tests {
		t.Run(strings.Join(flags, "_"), func(t *testing.T) {
			t.Parallel()

			var called atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called.Store(true)
			}))
			t.Cleanup(server.Close)
			outputPath := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			args := append([]string{"http", server.URL}, flags...)
			args = append(args, "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			require.Error(t, err, "incompatible output options succeeded")
			require.ErrorIs(t, err, errInvalidHTTPFlags)
			assert.False(t, called.Load(), "server received invalid request")
			contents, readErr := os.ReadFile(outputPath)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(contents), "existing output")
		})
	}
}

func TestHTTPRemovedIncludeFlagDoesNotSendRequestOrOpenOutput(t *testing.T) {
	t.Parallel()

	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called.Store(true)
	}))
	t.Cleanup(server.Close)
	outputPath := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	_, _, err := executeRootStreams(t, "http", server.URL, "--include", "--output", outputPath)
	require.Error(t, err, "removed flag succeeded")
	assert.Contains(t, err.Error(), "unknown flag: --include")
	assert.False(t, called.Load(), "server received request with removed flag")
	contents, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(contents), "existing output")
}

func TestHTTPStatusFailurePreservesResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
		writeHTTPTestString(t, writer, "short and stout")
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	require.Error(t, err)
	assert.Equal(t, "short and stout", stdout)

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--fail=false")
	require.NoError(t, err, "HTTP 418 with --fail=false: %v", err)
	assert.Equal(t, "short and stout", stdout)
}

func TestHTTPRedirectBehavior(t *testing.T) {
	t.Parallel()

	t.Run("replays in-memory body", func(t *testing.T) {
		t.Parallel()

		type requestRecord struct{ method, body string }
		received := make(chan requestRecord, 1)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/start" {
				writer.Header().Set("Location", "/final")
				writer.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read replayed request body: %v", err)
				return
			}
			received <- requestRecord{method: request.Method, body: string(body)}
			writeHTTPTestString(t, writer, "final")
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeRootStreams(t, "http", "-X", "POST", server.URL+"/start", "--data", "replay me")
		require.NoError(t, err, "follow replayable redirect")
		require.Equal(t, "final", stdout, "final response")
		record := <-received
		assert.Equal(t, http.MethodPost, record.method, "redirected method")
		assert.Equal(t, "replay me", record.body, "redirected body")
	})

	t.Run("follow false returns redirect", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Location", "/unused")
			writer.WriteHeader(http.StatusTemporaryRedirect)
			writeHTTPTestString(t, writer, "redirect response")
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeRootStreams(t, "http", server.URL, "--follow=false")
		require.NoError(t, err, "HTTP --follow=false")
		assert.Equal(t, "redirect response", stdout, "redirect response body")
	})

	t.Run("303 JSON envelope uses final method and URL", func(t *testing.T) {
		t.Parallel()

		finalMethod := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/start" {
				writer.Header().Set("Location", "/final")
				writer.WriteHeader(http.StatusSeeOther)
				return
			}
			finalMethod <- request.Method
			writeHTTPTestString(t, writer, "final")
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeRootStreams(
			t,
			"http", "-X", "POST", server.URL+"/start",
			"--data", "request body", "--select", "response", "--format", "json",
		)
		require.NoError(t, err, "follow 303 redirect")
		envelope := decodeHTTPEnvelope(t, stdout)
		require.Equal(t, http.MethodGet, envelope.Method, "final request method")
		require.Equal(t, server.URL+"/final", envelope.URL, "final request URL")
		assert.Equal(t, http.MethodGet, <-finalMethod, "server method")
	})

	t.Run("replays multipart file body", func(t *testing.T) {
		t.Parallel()

		uploadPath := filepath.Join(t.TempDir(), "report.txt")
		require.NoError(t, os.WriteFile(uploadPath, []byte("redirected upload"), 0o600))
		type multipartRecord struct {
			err   error
			field string
			file  string
		}
		received := make(chan multipartRecord, 1)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/start" {
				if err := request.ParseMultipartForm(1 << 20); err != nil {
					t.Errorf("parse initial multipart request: %v", err)
					return
				}
				writer.Header().Set("Location", "/final")
				writer.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			record := multipartRecord{}
			if err := request.ParseMultipartForm(1 << 20); err != nil {
				record.err = err
			} else {
				record.field = request.FormValue("name")
				file, _, err := request.FormFile("attachment")
				if err != nil {
					record.err = err
				} else {
					contents, readErr := io.ReadAll(file)
					record.file = string(contents)
					record.err = errors.Join(readErr, file.Close())
				}
			}
			received <- record
			writeHTTPTestString(t, writer, "final")
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeRootStreams(
			t,
			"http", "-X", "POST", server.URL+"/start",
			"--form", "name=demo", "--file", "attachment="+uploadPath,
		)
		require.NoError(t, err, "follow multipart redirect")
		require.Equal(t, "final", stdout, "final response")
		record := <-received
		require.NoError(t, record.err, "parse replayed multipart request")
		assert.Equal(t, "demo", record.field, "replayed multipart field")
		assert.Equal(t, "redirected upload", record.file, "replayed multipart file")
	})

	t.Run("non-replayable stdin preserves redirect", func(t *testing.T) {
		t.Parallel()

		var finalCalled atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/start" {
				if _, err := io.Copy(io.Discard, request.Body); err != nil {
					t.Errorf("read streamed request body: %v", err)
					return
				}
				writer.Header().Set("Location", "/final")
				writer.WriteHeader(http.StatusTemporaryRedirect)
				writeHTTPTestString(t, writer, "redirect response")
				return
			}
			finalCalled.Store(true)
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeHTTPStreamsWithInput(
			t,
			strings.NewReader("streamed body"),
			"http", "-X", "POST", server.URL+"/start", "--input", "-",
		)
		require.Error(t, err, "non-replayable 307 redirect succeeded")
		assert.Equal(t, "redirect response", stdout, "redirect response body")
		assert.False(t, finalCalled.Load(), "non-replayable request followed redirect")
	})

	t.Run("redirect limit preserves last response", func(t *testing.T) {
		t.Parallel()

		var beyondLimitCalled atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/start":
				writer.Header().Set("Location", "/last")
				writer.WriteHeader(http.StatusFound)
			case "/last":
				writer.Header().Set("Location", "/beyond")
				writer.WriteHeader(http.StatusFound)
				writeHTTPTestString(t, writer, "redirect limit response")
			case "/beyond":
				beyondLimitCalled.Store(true)
			}
		}))
		t.Cleanup(server.Close)

		stdout, _, err := executeRootStreams(t, "http", server.URL+"/start", "--max-redirects", "1")
		require.Error(t, err, "redirect limit succeeded")
		assert.Equal(t, "redirect limit response", stdout, "last redirect response body")
		assert.False(t, beyondLimitCalled.Load(), "request exceeded redirect limit")
	})
}

func TestHTTPRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-t.Context().Done()
	}))
	// A request deadline may expire before the server can enter its handler.
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			<-t.Context().Done()
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	_, done := startCancellableHTTPRequest(t, server, nil,
		"http", server.URL, "--request-timeout", "50ms")
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("--request-timeout did not stop the request")
	}
}

func TestHTTPRequestCancellationReachesServer(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	requestCanceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-request.Context().Done():
			close(requestCanceled)
		case <-t.Context().Done():
		}
	}))
	t.Cleanup(server.Close)

	cancel, done := startCancellableHTTPRequest(t, server, nil, "http", server.URL)
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("request ended before handler entry: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server handler did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("request ended before cancellation: %v", err)
	default:
	}
	select {
	case <-requestCanceled:
		t.Fatal("server request context canceled before parent cancellation")
	default:
	}
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not stop the request")
	}
	select {
	case <-requestCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("server request context was not canceled")
	}
}

func TestHTTPSetupTimeoutStopsBlockedTLSHandshake(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close TLS test listener: %v", err)
		}
	})
	accepted := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		close(accepted)
		deadlineErr := connection.SetDeadline(time.Now().Add(time.Second))
		_, readErr := io.Copy(io.Discard, connection)
		serverDone <- errors.Join(deadlineErr, readErr, connection.Close())
	}()

	requestDone := make(chan error, 1)
	go func() {
		_, _, requestErr := executeRootStreams(
			t,
			"http", "https://"+listener.Addr().String(),
			"--insecure", "--timeout", "50ms", "--request-timeout", "0",
		)
		requestDone <- requestErr
	}()
	select {
	case <-accepted:
	case requestErr := <-requestDone:
		t.Fatalf("request ended before the blocking TLS connection was accepted: %v", requestErr)
	case <-time.After(time.Second):
		t.Fatal("TLS test listener did not accept the request")
	}

	select {
	case requestErr := <-requestDone:
		require.Error(t, requestErr, "blocked TLS handshake succeeded")
		var networkErr net.Error
		deadline := errors.Is(requestErr, context.DeadlineExceeded)
		networkTimeout := errors.As(requestErr, &networkErr) && networkErr.Timeout()
		if !deadline && !networkTimeout {
			t.Fatalf("error = %v, want a setup timeout", requestErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("--timeout did not stop the blocked TLS handshake")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking TLS server did not observe connection shutdown")
	}
}

func TestHTTPRequestCancellationInterruptsBlockedUpload(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	bodyRead := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		_, err := io.Copy(io.Discard, request.Body)
		bodyRead <- err
	}))
	t.Cleanup(server.Close)
	input := newBlockingReadCloser()
	cancel, done := startCancellableHTTPRequest(t, server, input,
		"http", "-X", "POST", server.URL, "--input", "-")

	for _, ready := range []struct {
		done <-chan struct{}
		name string
	}{
		{started, "server handler"},
		{input.started, "stdin read"},
	} {
		select {
		case <-ready.done:
		case err := <-done:
			t.Fatalf("request ended before %s started: %v", ready.name, err)
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not start", ready.name)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("request ended before cancellation: %v", err)
	default:
	}
	select {
	case <-input.closed:
		t.Fatal("blocked stdin closed before cancellation")
	default:
	}
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not interrupt blocked upload")
	}
	select {
	case <-input.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked stdin was not closed")
	}
	select {
	case err := <-bodyRead:
		require.Error(t, err, "canceled upload completed without a body read error")
	case <-time.After(2 * time.Second):
		t.Fatal("server remained blocked reading canceled upload")
	}
}

func TestHTTPMultipartEarlyResponseDoesNotHang(t *testing.T) {
	t.Parallel()

	uploadPath := filepath.Join(t.TempDir(), "large-upload.bin")
	require.NoError(t, os.WriteFile(uploadPath, bytes.Repeat([]byte("x"), 4<<20), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		writeHTTPTestString(t, writer, "upload rejected")
	}))
	t.Cleanup(server.Close)

	type result struct {
		err    error
		stdout string
	}
	done := make(chan result, 1)
	go func() {
		stdout, _, err := executeRootStreams(
			t,
			"http", "-X", "POST", server.URL,
			"--file", "attachment="+uploadPath,
		)
		done <- result{stdout: stdout, err: err}
	}()
	select {
	case got := <-done:
		require.Error(t, got.err, "HTTP 413 succeeded")
		assert.Equal(t, "upload rejected", got.stdout, "rejection body")
	case <-time.After(2 * time.Second):
		t.Fatal("multipart request hung after early response")
	}
}

func TestHTTPCommandTreeCanExecuteMoreThanOnce(t *testing.T) {
	t.Parallel()

	received := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read reused-tree request body: %v", err)
			return
		}
		received <- string(body)
		writeHTTPTestString(t, writer, "ok")
	}))
	t.Cleanup(server.Close)

	root := newRootCmd()
	for _, body := range []string{"first", "second"} {
		var output bytes.Buffer
		root.SetIn(strings.NewReader(body))
		root.SetOut(&output)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"http", "-X", "POST", server.URL})
		require.NoError(t, executeCommand(root), "HTTP request with %q", body)
		require.Equal(t, "ok", output.String(), "response body")
		assert.Equal(t, body, <-received, "request body")
	}
}

func TestHTTPPrivateCAAndHTTP2(t *testing.T) {
	t.Parallel()

	protocol := make(chan int, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		protocol <- request.ProtoMajor
		writeHTTPTestString(t, writer, "secure")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certificate := server.Certificate()
	require.NotNil(t, certificate, "TLS server certificate")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--ca", caPath)
	require.NoError(t, err, "HTTP with private CA: %v", err)
	assert.Equal(t, "secure", stdout)
	assert.Equal(t, 2, <-protocol, "HTTP protocol major")
}

func TestHTTPMutualTLS(t *testing.T) {
	t.Parallel()

	identity := createNetworkTestIdentity(t)
	serverIdentity, err := tls.LoadX509KeyPair(identity.serverCert, identity.serverKey)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(identity.caCert)
	require.NoError(t, err)
	clientRoots := x509.NewCertPool()
	require.True(t, clientRoots.AppendCertsFromPEM(caPEM), "append client CA")

	peerCertificates := make(chan int, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peerCertificates <- len(request.TLS.PeerCertificates)
		writeHTTPTestString(t, writer, "mutual TLS")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverIdentity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(
		t,
		"http", server.URL,
		"--ca", identity.caCert,
		"--servername", "localhost",
		"--cert", identity.clientCert,
		"--key", identity.clientKey,
	)
	require.NoError(t, err, "mutual TLS HTTP request: %v", err)
	assert.Equal(t, "mutual TLS", stdout)
	assert.NotZero(t, <-peerCertificates, "server received no client certificate")
}

func TestHTTPTruncatedResponseReportsPartialOutput(t *testing.T) {
	t.Parallel()

	server := newTruncatedHTTPServer(t)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	require.Error(t, err)
	assert.Equal(t, "abc", stdout)

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--select", "response", "--format", "json")
	require.Error(t, err)
	envelope := decodeHTTPEnvelope(t, stdout)
	assert.False(t, envelope.Complete, "truncated response completion")
	assert.NotEmpty(t, envelope.Error, "truncated response error")
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("abc")), envelope.Body, "partial base64 response")

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--select", "body", "--format", "json")
	require.Error(t, err)
	bodyReport := decodeHTTPEnvelope(t, stdout)
	assert.False(t, bodyReport.Complete, "truncated body completion")
	assert.NotEmpty(t, bodyReport.Error, "truncated body error")
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("abc")), bodyReport.Body, "partial base64 body")
}

func TestHTTPOutputWriteFailureReturnsPartialOutput(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "response body")
	}))
	t.Cleanup(server.Close)

	output := &failAfterWriter{err: errHTTPTestOutputFailed, remaining: 4}
	err := executeHTTPWithWriters(t, strings.NewReader(""), output, io.Discard, "http", server.URL)
	require.ErrorIs(t, err, output.err)
	assert.Equal(t, "resp", output.output.String(), "partial output")
}

type httpResponseEnvelope struct {
	Headers      map[string][]string `json:"headers"`
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Status       string              `json:"status"`
	Protocol     string              `json:"protocol"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
	Error        string              `json:"error,omitempty"`
	Trace        json.RawMessage     `json:"trace,omitempty"`
	StatusCode   int                 `json:"status_code"`
	Complete     bool                `json:"complete"`
}

func decodeHTTPEnvelope(t *testing.T, output string) httpResponseEnvelope {
	t.Helper()
	var envelope httpResponseEnvelope
	require.NoError(t, json.Unmarshal([]byte(output), &envelope), "decode JSON response %q", output)
	return envelope
}

func executeHTTPStreamsWithInput(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := executeHTTPWithWriters(t, input, &stdout, &stderr, args...)
	return stdout.String(), stderr.String(), err
}

func executeHTTPWithWriters(
	t *testing.T,
	input io.Reader,
	output io.Writer,
	diagnostics io.Writer,
	args ...string,
) error {
	t.Helper()
	root := newRootCmd()
	root.SetIn(input)
	root.SetOut(output)
	root.SetErr(diagnostics)
	root.SetArgs(args)
	return commandio.Execute(root)
}

type countingReader struct {
	source io.Reader
	reads  atomic.Int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.reads.Add(1)
	return reader.source.Read(buffer) //nolint:wrapcheck // preserve the wrapped reader's stream semantics
}

type failAfterWriter struct {
	err       error
	output    bytes.Buffer
	remaining int
}

type blockingReadCloser struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{started: make(chan struct{}), closed: make(chan struct{})}
}

func (reader *blockingReadCloser) Read([]byte) (int, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, errHTTPTestInputClosed
}

func (reader *blockingReadCloser) Close() error {
	reader.closeOnce.Do(func() { close(reader.closed) })
	return nil
}

func (writer *failAfterWriter) Write(buffer []byte) (int, error) {
	if writer.remaining == 0 {
		return 0, writer.err
	}
	write := min(len(buffer), writer.remaining)
	written, err := writer.output.Write(buffer[:write])
	if err != nil {
		return written, fmt.Errorf("capture partial output: %w", err)
	}
	writer.remaining -= write
	if write != len(buffer) {
		return write, writer.err
	}
	return write, nil
}

func writeHTTPTestString(t *testing.T, writer io.Writer, value string) {
	t.Helper()
	if _, err := io.WriteString(writer, value); err != nil {
		t.Errorf("write HTTP test response: %v", err)
	}
}

func writeHTTPTestBytes(t *testing.T, writer io.Writer, value []byte) {
	t.Helper()
	if _, err := writer.Write(value); err != nil {
		t.Errorf("write HTTP test response: %v", err)
	}
}

func newTruncatedHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("response writer does not support hijacking")
			return
		}
		connection, buffer, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack response: %v", err)
			return
		}
		_, writeErr := fmt.Fprint(buffer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
		flushErr := buffer.Flush()
		if err := errors.Join(writeErr, flushErr, connection.Close()); err != nil {
			t.Errorf("write truncated response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
