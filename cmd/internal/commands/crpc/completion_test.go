package crpc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestCRPCCompletionUsesSchemasWithoutOperationalIO(t *testing.T) {
	t.Parallel()
	path := writeProtoset(t, schemaSet(true))
	output := filepath.Join(t.TempDir(), "unchanged")
	require.NoError(t, os.WriteFile(output, []byte("keep"), 0o600))
	for _, test := range []struct {
		want string
		args []string
	}{
		{"example.v1.EchoService\tservice", []string{"--protoset", path, "--list", "example.v1.E"}},
		{"example.v1.Request\tmessage", []string{"--protoset", path, "--describe", "example.v1.R"}},
		{"example.v1.EchoService/Echo\tserver:", []string{"--protoset", path, "--template", "example.v1.EchoService/E"}},
		{"example.v1.EchoService/Echo\tserver:", []string{"--style", "plain", "--protoset", path, "--template", "example.v1.EchoService/E"}},
		{`{"text":""}` + "\texample.v1.Request", []string{"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--data="}},
		{"example.v1.EchoService/Echo\tserver:", []string{"http://127.0.0.1:1", "--protoset", path, "-i", "-", "-o", output, "example.v1.EchoService/E"}},
	} {
		stdout, _, err := run(t, &unexpectedInput{t: t}, append([]string{"__complete", "crpc"}, test.args...)...)
		require.NoError(t, err)
		assert.Contains(t, stdout, test.want)
	}
	after, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(after))
	stdout, _, err := run(t, nil, "__complete", "crpc", "http://127.0.0.1:1", "--protoset", path, "--stream", "unary", "example.v1.EchoService/E")
	require.NoError(t, err)
	assert.Equal(t, ":4\n", stdout, "incompatible streaming methods must not be suggested")
	for _, test := range []struct{ flag, want string }{
		{"--format", "jsonl\n:4\n"},
		{"--stream", "server\tOne request and many responses\n:4\n"},
		{"--data", templateCompletion},
	} {
		stdout, _, err = run(t, nil, "__complete", "crpc", "http://127.0.0.1:1"+echoMethod, "--protoset", path, test.flag, "")
		require.NoError(t, err)
		assert.Equal(t, test.want, stdout)
	}
}

// templateCompletion is the completion protocol output offering example.v1.Request's template.
var templateCompletion = `{"text":""}` + "\texample.v1.Request\n:4\n"

func TestCRPCDataCompletionIsQuietWithoutAUsableTemplate(t *testing.T) {
	t.Parallel()
	path := writeProtoset(t, schemaSet(false))
	large := schemaSet(false)
	request := large.File[0].MessageType[0]
	for i := range 96 {
		request.Field = append(request.Field, &descriptorpb.FieldDescriptorProto{
			Name: new(fmt.Sprintf("long_template_field_name_%02d", i)), Number: new(int32(100 + i)),
			Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
		})
	}
	largePath := writeProtoset(t, large)
	for name, args := range map[string][]string{
		"discovery":                  {"http://127.0.0.1:1", "--protoset", path, "--data", ""},
		"input owns the request":     {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--input", "unread.json", "--data", ""},
		"empty list conflicts":       {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--list=", "--data", ""},
		"empty describe conflicts":   {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--describe=", "--data", ""},
		"empty template conflicts":   {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--template=", "--data", ""},
		"auth file from stdin":       {"https://127.0.0.1:1" + echoMethod, "--protoset", path, "--auth-bearer-file", "-", "--data", ""},
		"CA from stdin":              {"https://127.0.0.1:1" + echoMethod, "--protoset", path, "--ca", "-", "--data", ""},
		"auth conflict hides stdin":  {"https://127.0.0.1:1" + echoMethod, "--protoset", path, "--auth-bearer", "token", "--auth-basic-file", "-", "--data", ""},
		"missing method":             {"http://127.0.0.1:1/example.v1.EchoService/Missing", "--protoset", path, "--data", ""},
		"unrelated prefix":           {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--data", `{"other`},
		"template larger than 2 KiB": {"http://127.0.0.1:1" + echoMethod, "--protoset", largePath, "--data", ""},
		"cert without key":           {"https://127.0.0.1:1" + echoMethod, "--protoset", path, "--cert", "client.pem", "--data", ""},
		"missing CA file":            {"https://127.0.0.1:1" + echoMethod, "--protoset", path, "--ca", "missing.pem", "--data", ""},
		"template is not base64":     {"http://127.0.0.1:1" + echoMethod, "--protoset", path, "--input-encoding", "base64", "--data", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := run(t, nil, append([]string{"__complete", "crpc"}, args...)...)
			require.NoError(t, err)
			assert.Equal(t, ":4\n", stdout)
		})
	}
	stdout, _, err := run(t, nil, "__complete", "crpc", "http://127.0.0.1:1"+echoMethod, "--protoset", path, "--data", `'{"te`)
	require.NoError(t, err)
	assert.Equal(t, templateCompletion, stdout, "an opening shell quote still matches the template")
}

func TestCRPCCompletionHidesInapplicableFlags(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ args, absent []string }{
		{[]string{"http://example.test", "--data", "{}"}, []string{"--input", "--stdin", "--list", "--describe", "--template", "--cert", "--insecure"}},
		{[]string{"--protoset", "schema.pb", "--list", "example.Service"}, []string{"--data", "--input", "--stream", "--wait", "--reflect"}},
	} {
		output, _, err := run(t, nil, append(append([]string{"__complete", "crpc"}, test.args...), "--")...)
		require.NoError(t, err)
		for _, absent := range test.absent {
			assert.NotContains(t, output, absent+"\t")
		}
	}
	for _, flag := range []string{"--list", "--describe", "--template"} {
		t.Run("stream values with "+flag, func(t *testing.T) {
			t.Parallel()
			output, _, err := run(t, &unexpectedInput{t: t}, "__complete", "crpc", flag, "example.Service", "--stream", "")
			require.NoError(t, err)
			assert.Equal(t, ":4\n", output, "discovery must not suggest invocation modes")
		})
	}
}

func TestCRPCReflectionCompletionReusesHeadersAndDoesNotInvoke(t *testing.T) {
	t.Parallel()
	server, calls := schemaServer(t, schemaSet(false), "", func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			info, _ := connect.CallInfoForServerContext(ctx)
			assert.Equal(t, []string{"first", "second"}, info.RequestHeader().Values("X-Auth"))
			return next(ctx, spec, stream)
		}
	})
	output, _, err := run(t, nil, "__complete", "crpc", server.URL, "-H", "X-Auth: first", "-H", "X-Auth: second", "example.v1.EchoService/E")
	require.NoError(t, err)
	assert.Contains(t, output, "example.v1.EchoService/Echo")
	assert.Zero(t, calls.Load())
}

func TestCRPCCompletionSkipsLinesExecutionRejects(t *testing.T) {
	t.Parallel()
	path := writeProtoset(t, schemaSet(false))
	// Each line is completed against its own server; "{server}" names its URL.
	for _, test := range []struct {
		name string
		args []string
	}{
		{"URL already names a method", []string{"{server}" + echoMethod, "example.v1.EchoService/"}},
		{"stdin beside data", []string{"{server}" + echoMethod, "--stdin", "always", "--data", ""}},
		{"jsonl discovery", []string{"{server}", "--format", "jsonl", "--list", ""}},
		{"json for a server stream", []string{"{server}" + echoMethod, "--stream", "server", "--format", "json", "--data", ""}},
		{"malformed data", []string{"{server}", "-d", "not-json", "example.v1.EchoService/"}},
		{"missing input file", []string{"{server}", "-i", "missing.json", "example.v1.EchoService/"}},
		{"empty input path", []string{"{server}", "-i", "", "example.v1.EchoService/"}},
		{"timeout shorthand absorbs -d", []string{"{server}" + echoMethod, "-td", ""}},
		{"assignment after separator is positional", []string{"{server}", "--", "--data=example.v1.EchoService/"}},
		{"protoset with empty bearer token", []string{"https://127.0.0.1:1", "--protoset", path, "--auth-bearer", "", "example.v1.EchoService/"}},
		{"protoset without a matching method", []string{"http://127.0.0.1:1", "--protoset", path, "--stream", "bidi", "example.v1.EchoService/"}},
		{"protoset with unparseable URL", []string{"not a URL", "--protoset", path, "--list", ""}},
		{"protoset with system CA alone", []string{"https://127.0.0.1:1", "--protoset", path, "--system-ca", "example.v1.EchoService/"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler, calls := schemaHandler(t, schemaSet(false), "")
			var requests atomic.Int32
			server := startSchemaServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				handler.ServeHTTP(writer, request)
			}))
			args := []string{"__complete", "crpc"}
			for _, arg := range test.args {
				args = append(args, strings.ReplaceAll(arg, "{server}", server.URL))
			}
			stdout, _, err := run(t, &unexpectedInput{t: t}, args...)
			require.NoError(t, err)
			assert.Equal(t, ":4\n", stdout)
			assert.Zero(t, requests.Load(), "completion reflected for a line execution rejects before using the network")
			assert.Zero(t, calls.Load())
		})
	}
}

func TestCRPCMethodCompletionFiltersByPrefixBeforeValidatingRequests(t *testing.T) {
	t.Parallel()
	set := schemaSet(false)
	wide := &descriptorpb.ServiceDescriptorProto{Name: new("WideService")}
	for i := range 2000 {
		wide.Method = append(wide.Method, &descriptorpb.MethodDescriptorProto{
			Name: new(fmt.Sprintf("M%04d", i)), InputType: new(".example.v1.Request"), OutputType: new(".example.v1.Request"),
		})
	}
	set.File[0].Service = append(set.File[0].Service, wide)
	path := writeProtoset(t, set)
	// Validating this request once per method, rather than only for the typed
	// prefix, takes far longer than the completion cap.
	request := `{"text":"` + strings.Repeat("x", 4<<20) + `"}`
	started := time.Now()
	stdout, _, err := run(t, &unexpectedInput{t: t}, "__complete", "crpc", "http://127.0.0.1:1", "--protoset", path,
		"-d", request, "example.v1.WideService/M0007")
	elapsed := time.Since(started)
	require.NoError(t, err)
	// Wall-clock margin as in the reflection deadline test: the 2-second cap plus slack.
	assert.Less(t, elapsed, 4*time.Second, "completion outlived its cap")
	assert.Equal(t, "example.v1.WideService/M0007\tunary: example.v1.Request -> example.v1.Request\n:4\n", stdout)
}

func TestCRPCReflectionCompletionDeadlineAndQuietFailure(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		<-request.Context().Done()
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	for _, budget := range []string{"0", "50ms"} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		root := cmd.NewCommand()
		root.SetContext(ctx)
		started := time.Now()
		output, diagnostics, err := testcmd.RunStreams(t, root, &unexpectedInput{t: t}, "__complete", "crpc", server.URL,
			"--connect-timeout", "0", "--reflection-timeout", budget, "example.v1.EchoService/E")
		elapsed := time.Since(started)
		cancel()
		require.NoError(t, err)
		assert.Equal(t, ":4\n", string(output))
		assert.NotContains(t, string(diagnostics), "deadline")
		ceiling := 4 * time.Second
		if budget == "50ms" {
			ceiling = time.Second
		}
		assert.Less(t, elapsed, ceiling, "completion did not apply its own deadline")
	}
	assert.EqualValues(t, 2, calls.Load())
}

func TestCRPCCompletionDoesNotReadCredentialStdin(t *testing.T) {
	t.Parallel()
	output, _, err := run(t, &unexpectedInput{t: t}, "__complete", "crpc", "https://example.test", "--ca", "-", "example.v1.Service/M")
	require.NoError(t, err)
	assert.Equal(t, ":4\n", output)
}

func TestCRPCCompletionFailureDoesNotPrintServerMessages(t *testing.T) {
	t.Parallel()
	server, _ := schemaServer(t, schemaSet(false), "", func(connect.ServerFunc) connect.ServerFunc {
		return func(context.Context, connect.Spec, connect.ServerStream) error {
			return connect.NewError(connect.CodePermissionDenied, "private server details")
		}
	})
	output, diagnostics, err := run(t, strings.NewReader(""), "__complete", "crpc", server.URL, "example.v1.Service/M")
	require.NoError(t, err)
	assert.Equal(t, ":4\n", output)
	assert.NotContains(t, diagnostics, "private server details")
}
