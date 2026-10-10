package crpc_test

import (
	"context"
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
	} {
		stdout, _, err = run(t, nil, "__complete", "crpc", "http://127.0.0.1:1"+echoMethod, "--protoset", path, test.flag, "")
		require.NoError(t, err)
		assert.Equal(t, test.want, stdout)
	}
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
