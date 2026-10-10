package crpc_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleCRPCCallsWithoutSchemas(t *testing.T) {
	t.Parallel()
	server := echoServer(t, false, false)
	for _, args := range [][]string{
		{"crpc", server.URL + echoMethod, "-d", `{"text":"hello"}`},
		{"connectrpc", server.URL, strings.TrimPrefix(echoMethod, "/"), "-d", `{"text":"hello"}`},
	} {
		output, diagnostics, err := run(t, nil, args...)
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"hello"}`, output)
		assert.Empty(t, diagnostics)
	}
}

func TestExampleCRPCReadsPipedJSON(t *testing.T) {
	t.Parallel()
	server := echoServer(t, false, false)
	output, _, err := run(t, strings.NewReader(`{"text":"from stdin"}`), "crpc", server.URL+echoMethod)
	require.NoError(t, err)
	assert.JSONEq(t, `{"text":"from stdin"}`, output)

	output, _, err = run(t, nil, "crpc", server.URL+echoMethod, "--stdin", "never")
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, output)
}

const echoMethod = "/example.v1.EchoService/Echo"

func echoServer(t *testing.T, secure, http2 bool) *httptest.Server {
	t.Helper()
	service := connect.NewServer()
	service.Register(connect.Method{
		Spec: connect.Spec{Procedure: echoMethod},
		Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			var message structpb.Struct
			if err := stream.Receive(&message); err != nil {
				return fmt.Errorf("receive fixture request: %w", err)
			}
			return stream.Send(&message)
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service, connecthttp.WithRequireConnectProtocolHeader())
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = http2
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func run(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	if input == nil {
		input = strings.NewReader("")
	}
	root := cmd.NewCommand()
	root.SetContext(t.Context())
	output, diagnostics, err := testcmd.RunStreams(t, root, input, args...)
	return string(output), string(diagnostics), err
}
