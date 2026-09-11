package cmd

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
	"sync/atomic"
	"testing"
	"time"

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
			if err != nil {
				t.Fatalf("http %s: %v", test.methodArg, err)
			}
			if method := <-gotMethod; method != test.wantMethod {
				t.Fatalf("method = %q, want %q", method, test.wantMethod)
			}
			if test.wantMethod == http.MethodHead {
				if !strings.Contains(stdout, "204 No Content") || !strings.Contains(stdout, "X-Http-Test") {
					t.Fatalf("HEAD output = %q, want status and headers", stdout)
				}
				return
			}
			if stdout != "ok" {
				t.Fatalf("stdout = %q, want response body", stdout)
			}
		})
	}
}

func TestBareHTTPShowsHelpWithoutOpeningIO(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "existing-output")
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := &countingReader{source: strings.NewReader("must not be read")}
	stdout, _, err := executeHTTPStreamsWithInput(t, input, "http", "--output", outputPath)
	if err != nil {
		t.Fatalf("bare HTTP command: %v", err)
	}
	if !strings.Contains(stdout, "Make an HTTP request") {
		t.Fatalf("stdout = %q, want HTTP help", stdout)
	}
	if input.reads.Load() != 0 {
		t.Fatal("bare HTTP command read stdin")
	}
	contents, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(contents) != "preserve" {
		t.Fatalf("output = %q, want preserved contents", contents)
	}
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
			if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			input := &countingReader{source: strings.NewReader("unread")}
			commandArgs := append([]string{"http", server.URL, "--output", outputPath}, args...)
			_, _, err := executeHTTPStreamsWithInput(t, input, commandArgs...)
			if err == nil {
				t.Fatal("invalid method arguments succeeded")
			}
			if called.Load() || input.reads.Load() != 0 {
				t.Fatal("invalid method arguments performed I/O")
			}
			contents, err := os.ReadFile(outputPath)
			if err != nil || string(contents) != "preserve" {
				t.Fatalf("output = %q, error = %v", contents, err)
			}
		})
	}
}

func TestHTTPMethodCompletion(t *testing.T) {
	t.Parallel()
	stdout, _, err := executeRootStreams(t, "__complete", "http", "--method", "P")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		if !strings.Contains(stdout, method+"\n") {
			t.Fatalf("method completion = %q, missing %s", stdout, method)
		}
	}
}

func TestHTTPDefaultURLScheme(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ input, want string }{
		{"example.com", "https://example.com"},
		{"localhost:8443/path?q=one", "https://localhost:8443/path?q=one"},
		{"[::1]:8443/path", "https://[::1]:8443/path"},
		{"//example.com/path", "https://example.com/path"},
		{"example.com/?next=http://other.test", "https://example.com/?next=http://other.test"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			_, address, err := httpMethodURL(command, []string{test.input})
			if err != nil {
				t.Fatal(err)
			}
			if address.String() != test.want {
				t.Fatalf("URL = %q, want %q", address, test.want)
			}
		})
	}
	for _, input := range []string{"", "/path", "http://", "ftp://example.com", "localhost:bad", "http:/example.com", "https:/example.com"} {
		t.Run("invalid/"+input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			if _, _, err := httpMethodURL(command, []string{input}); err == nil {
				t.Fatalf("invalid URL %q accepted", input)
			}
		})
	}
}

func TestHTTPRequestBodySources(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	rawPath := filepath.Join(directory, "request.bin")
	jsonPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(rawPath, []byte("file bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, []byte(`{"source":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}

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
			if err != nil {
				t.Fatalf("HTTP request: %v", err)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want no diagnostics", stderr)
			}
			if stdout != "received" {
				t.Fatalf("stdout = %q, want response body", stdout)
			}
			record := <-received
			if record.body != test.wantBody {
				t.Fatalf("request body = %q, want %q", record.body, test.wantBody)
			}
			if record.contentType != test.wantContentType {
				t.Fatalf("Content-Type = %q, want %q", record.contentType, test.wantContentType)
			}
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
	if err != nil {
		t.Fatalf("HTTP encoded input: %v", err)
	}
	if body := <-received; body != "decoded bytes" {
		t.Fatalf("request body = %q, want decoded bytes", body)
	}
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
		if err != nil {
			t.Fatalf("HTTP form request: %v", err)
		}
		record := <-received
		if record.contentType != "application/x-www-form-urlencoded" {
			t.Fatalf("Content-Type = %q, want form encoding", record.contentType)
		}
		if !slices.Equal(record.values, []string{"first", "second"}) {
			t.Fatalf("form values = %q, want repeated values", record.values)
		}
	})

	t.Run("multipart file and field", func(t *testing.T) {
		t.Parallel()

		uploadPath := filepath.Join(t.TempDir(), "report.txt")
		if err := os.WriteFile(uploadPath, []byte("report contents"), 0o600); err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatalf("HTTP multipart request: %v", err)
		}
		record := <-received
		if record.err != nil {
			t.Fatalf("parse multipart request: %v", record.err)
		}
		if record.field != "demo" || record.filename != "report.txt" || record.file != "report contents" {
			t.Fatalf("multipart record = %+v", record)
		}
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
	if err != nil {
		t.Fatalf("HTTP headers: %v", err)
	}
	if values := <-received; !slices.Equal(values, []string{"first", "second"}) {
		t.Fatalf("header values = %q, want repeated values", values)
	}
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
				if _, _, err := executeRootStreams(t, args...); err != nil {
					t.Fatal(err)
				}
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
			if err != nil {
				t.Fatalf("HTTP stdin policy: %v", err)
			}
			if body := <-received; body != test.wantBody {
				t.Fatalf("request body = %q, want %q", body, test.wantBody)
			}
			if gotRead := input.reads.Load() > 0; gotRead != test.wantRead {
				t.Fatalf("stdin read = %t, want %t", gotRead, test.wantRead)
			}
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
			if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}

			args := append([]string{"http", server.URL}, test.args...)
			args = append(args, "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			if err == nil {
				t.Fatal("invalid body selection succeeded")
			}
			if called.Load() {
				t.Fatal("server received request before body validation")
			}
			contents, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != "preserve" {
				t.Fatalf("output = %q, want preserved contents", contents)
			}
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
			if err := os.WriteFile(path, []byte("preserve source"), 0o600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(server.Close)

			args := append([]string{"http", "-X", "POST", server.URL}, test.flag(path)...)
			args = append(args, "--output", path)
			_, _, err := executeRootStreams(t, args...)
			if err == nil {
				t.Fatal("source/output collision succeeded")
			}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != "preserve source" {
				t.Fatalf("source = %q, want preserved contents", contents)
			}
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

	stdout, stderr, err := executeRootStreams(t, "http", "-X", "GET", server.URL, "--format", "json", "--trace")
	if err != nil {
		t.Fatalf("HTTP JSON response: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want trace in JSON only", stderr)
	}
	envelope := decodeHTTPEnvelope(t, stdout)
	if envelope.Method != http.MethodGet || envelope.URL != server.URL {
		t.Fatalf("request identity = %s %s", envelope.Method, envelope.URL)
	}
	if envelope.StatusCode != http.StatusOK || envelope.Status != "200 OK" {
		t.Fatalf("status = %d %q", envelope.StatusCode, envelope.Status)
	}
	if !strings.HasPrefix(envelope.Protocol, "HTTP/") {
		t.Fatalf("protocol = %q, want HTTP version", envelope.Protocol)
	}
	if !slices.Equal(envelope.Headers["X-Npc-Test"], []string{"first", "second"}) {
		t.Fatalf("headers = %#v", envelope.Headers)
	}
	if envelope.BodyEncoding != "base64" || envelope.Body != base64.StdEncoding.EncodeToString(responseBody) {
		t.Fatalf("body = %q (%s), want base64 response", envelope.Body, envelope.BodyEncoding)
	}
	if !envelope.Complete || envelope.Error != "" {
		t.Fatalf("completion = %t error = %q", envelope.Complete, envelope.Error)
	}
	if len(envelope.Trace) == 0 || bytes.Equal(envelope.Trace, []byte("null")) {
		t.Fatalf("trace = %s, want embedded trace", envelope.Trace)
	}
}

func TestHTTPTextTraceIsWrittenToStderr(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "body")
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL, "--trace")
	if err != nil {
		t.Fatalf("HTTP text trace: %v", err)
	}
	if stdout != "body" {
		t.Fatalf("stdout = %q, want response body only", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatal("stderr is empty, want trace diagnostics")
	}
}

func TestHTTPIncludeAndOutputEncoding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-NPC-Test", "included")
		writeHTTPTestString(t, writer, "abc")
	}))
	t.Cleanup(server.Close)

	t.Run("include status and headers", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := executeRootStreams(t, "http", server.URL, "--include")
		if err != nil {
			t.Fatalf("HTTP include: %v", err)
		}
		if !strings.Contains(stdout, "200 OK") || !strings.Contains(stdout, "X-Npc-Test: included") || !strings.HasSuffix(stdout, "abc") {
			t.Fatalf("included output = %q", stdout)
		}
	})

	t.Run("encode body only", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := executeRootStreams(t, "http", server.URL, "--encoding", "base64")
		if err != nil {
			t.Fatalf("HTTP encoded response: %v", err)
		}
		if stdout != "YWJj" {
			t.Fatalf("stdout = %q, want base64 body", stdout)
		}
	})
}

func TestHTTPRejectsEnvelopeEncodingBeforeOutput(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"--include", "--encoding", "base64"},
		{"--format", "json", "--encoding", "base64"},
	}
	for _, flags := range tests {
		t.Run(strings.Join(flags, "_"), func(t *testing.T) {
			t.Parallel()

			outputPath := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"http", "http://127.0.0.1:1"}, flags...)
			args = append(args, "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			if err == nil {
				t.Fatal("incompatible output options succeeded")
			}
			contents, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != "preserve" {
				t.Fatalf("output = %q, want preserved contents", contents)
			}
		})
	}
}

func TestHTTPStatusFailurePreservesResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
		writeHTTPTestString(t, writer, "short and stout")
	}))
	t.Cleanup(server.Close)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	if err == nil {
		t.Fatal("HTTP 418 succeeded with default --fail")
	}
	if stdout != "short and stout" {
		t.Fatalf("stdout = %q, want error response body", stdout)
	}

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--fail=false")
	if err != nil {
		t.Fatalf("HTTP 418 with --fail=false: %v", err)
	}
	if stdout != "short and stout" {
		t.Fatalf("stdout = %q, want response body", stdout)
	}
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
		if err != nil {
			t.Fatalf("follow replayable redirect: %v", err)
		}
		if stdout != "final" {
			t.Fatalf("stdout = %q, want final response", stdout)
		}
		record := <-received
		if record.method != http.MethodPost || record.body != "replay me" {
			t.Fatalf("redirected request = %+v", record)
		}
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
		if err != nil {
			t.Fatalf("HTTP --follow=false: %v", err)
		}
		if stdout != "redirect response" {
			t.Fatalf("stdout = %q, want redirect response body", stdout)
		}
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
			"--data", "request body", "--format", "json",
		)
		if err != nil {
			t.Fatalf("follow 303 redirect: %v", err)
		}
		envelope := decodeHTTPEnvelope(t, stdout)
		if envelope.Method != http.MethodGet || envelope.URL != server.URL+"/final" {
			t.Fatalf("final request = %s %s, want GET %s/final", envelope.Method, envelope.URL, server.URL)
		}
		if method := <-finalMethod; method != http.MethodGet {
			t.Fatalf("server received method %q, want GET", method)
		}
	})

	t.Run("replays multipart file body", func(t *testing.T) {
		t.Parallel()

		uploadPath := filepath.Join(t.TempDir(), "report.txt")
		if err := os.WriteFile(uploadPath, []byte("redirected upload"), 0o600); err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatalf("follow multipart redirect: %v", err)
		}
		if stdout != "final" {
			t.Fatalf("stdout = %q, want final response", stdout)
		}
		record := <-received
		if record.err != nil {
			t.Fatalf("parse replayed multipart request: %v", record.err)
		}
		if record.field != "demo" || record.file != "redirected upload" {
			t.Fatalf("replayed multipart request = %+v", record)
		}
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
		if err == nil {
			t.Fatal("non-replayable 307 redirect succeeded")
		}
		if stdout != "redirect response" {
			t.Fatalf("stdout = %q, want redirect response body", stdout)
		}
		if finalCalled.Load() {
			t.Fatal("non-replayable request followed redirect")
		}
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
		if err == nil {
			t.Fatal("redirect limit succeeded")
		}
		if stdout != "redirect limit response" {
			t.Fatalf("stdout = %q, want last redirect response body", stdout)
		}
		if beyondLimitCalled.Load() {
			t.Fatal("request exceeded redirect limit")
		}
	})
}

func TestHTTPRequestTimeoutCancelsRequest(t *testing.T) {
	t.Parallel()

	requestCanceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
		close(requestCanceled)
	}))
	t.Cleanup(server.Close)

	_, _, err := executeRootStreams(t, "http", server.URL, "--request-timeout", "50ms")
	if err == nil {
		t.Fatal("timed-out request succeeded")
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("server request context was not canceled")
	}
}

func TestHTTPSetupTimeoutStopsBlockedTLSHandshake(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
		if requestErr == nil {
			t.Fatal("blocked TLS handshake succeeded")
		}
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

func TestHTTPRequestTimeoutInterruptsBlockedUpload(t *testing.T) {
	t.Parallel()

	bodyRead := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		_, err := io.Copy(io.Discard, request.Body)
		bodyRead <- err
	}))
	t.Cleanup(server.Close)
	input := newBlockingReadCloser()
	root := newRootCmd()
	root.SetIn(input)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"http", "-X", "POST", server.URL,
		"--input", "-",
		"--request-timeout", "50ms",
	})
	done := make(chan error, 1)
	go func() { done <- executeCommand(root) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked upload succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request timeout did not interrupt blocked upload")
	}
	select {
	case <-input.closed:
	case <-time.After(time.Second):
		t.Fatal("blocked stdin was not closed")
	}
	select {
	case <-bodyRead:
	case <-time.After(time.Second):
		t.Fatal("server remained blocked reading canceled upload")
	}
}

func TestHTTPMultipartEarlyResponseDoesNotHang(t *testing.T) {
	t.Parallel()

	uploadPath := filepath.Join(t.TempDir(), "large-upload.bin")
	if err := os.WriteFile(uploadPath, bytes.Repeat([]byte("x"), 4<<20), 0o600); err != nil {
		t.Fatal(err)
	}
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
		if got.err == nil {
			t.Fatal("HTTP 413 succeeded")
		}
		if got.stdout != "upload rejected" {
			t.Fatalf("stdout = %q, want rejection body", got.stdout)
		}
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
		if err := executeCommand(root); err != nil {
			t.Fatalf("HTTP request with %q: %v", body, err)
		}
		if output.String() != "ok" {
			t.Fatalf("output = %q, want ok", output.String())
		}
		if got := <-received; got != body {
			t.Fatalf("request body = %q, want %q", got, body)
		}
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
	if certificate == nil {
		t.Fatal("TLS server certificate is nil")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := executeRootStreams(t, "http", server.URL, "--ca", caPath)
	if err != nil {
		t.Fatalf("HTTP with private CA: %v", err)
	}
	if stdout != "secure" {
		t.Fatalf("stdout = %q, want secure response", stdout)
	}
	if got := <-protocol; got != 2 {
		t.Fatalf("HTTP protocol major = %d, want 2", got)
	}
}

func TestHTTPMutualTLS(t *testing.T) {
	t.Parallel()

	identity := createNetworkTestIdentity(t)
	serverIdentity, err := tls.LoadX509KeyPair(identity.serverCert, identity.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(identity.caCert)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append client CA")
	}

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
	if err != nil {
		t.Fatalf("mutual TLS HTTP request: %v", err)
	}
	if stdout != "mutual TLS" {
		t.Fatalf("stdout = %q, want mTLS response", stdout)
	}
	if got := <-peerCertificates; got == 0 {
		t.Fatal("server received no client certificate")
	}
}

func TestHTTPTruncatedResponseReportsPartialOutput(t *testing.T) {
	t.Parallel()

	server := newTruncatedHTTPServer(t)

	stdout, _, err := executeRootStreams(t, "http", server.URL)
	if err == nil {
		t.Fatal("truncated response succeeded")
	}
	if stdout != "abc" {
		t.Fatalf("stdout = %q, want partial response body", stdout)
	}

	stdout, _, err = executeRootStreams(t, "http", server.URL, "--format", "json")
	if err == nil {
		t.Fatal("truncated JSON response succeeded")
	}
	envelope := decodeHTTPEnvelope(t, stdout)
	if envelope.Complete || envelope.Error == "" {
		t.Fatalf("completion = %t error = %q", envelope.Complete, envelope.Error)
	}
	if envelope.Body != base64.StdEncoding.EncodeToString([]byte("abc")) {
		t.Fatalf("body = %q, want partial base64 response", envelope.Body)
	}
}

func TestHTTPOutputWriteFailureReturnsPartialOutput(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "response body")
	}))
	t.Cleanup(server.Close)

	output := &failAfterWriter{err: errHTTPTestOutputFailed, remaining: 4}
	err := executeHTTPWithWriters(t, strings.NewReader(""), output, io.Discard, "http", server.URL)
	if !errors.Is(err, output.err) {
		t.Fatalf("error = %v, want output failure", err)
	}
	if output.output.String() != "resp" {
		t.Fatalf("partial output = %q, want resp", output.output.String())
	}
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
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("decode JSON response %q: %v", output, err)
	}
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
	command, runErr := root.ExecuteC()
	return errors.Join(runErr, closeCommandIO(command))
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
	closed chan struct{}
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{closed: make(chan struct{})}
}

func (reader *blockingReadCloser) Read([]byte) (int, error) {
	<-reader.closed
	return 0, errHTTPTestInputClosed
}

func (reader *blockingReadCloser) Close() error {
	select {
	case <-reader.closed:
	default:
		close(reader.closed)
	}
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
