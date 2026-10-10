package crpc_test

import (
	"context"
	"encoding/json"
	"errors"
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

func TestExampleCRPCStreamsJSONLines(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"server", "client", "bidi"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			server := streamingServer(t, mode, false)
			input := `{"text":"one"}` + "\n" + `{"text":"two"}` + "\n"
			if mode == "server" {
				input = `{"text":"one"}`
			}
			output, _, err := run(t, strings.NewReader(input), "crpc", server.URL+echoMethod, "--stream", mode)
			require.NoError(t, err)
			if mode == "client" {
				assert.JSONEq(t, `{"count":2}`, output)
				return
			}
			lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
			require.Len(t, lines, 2)
			assert.JSONEq(t, `{"text":"one"}`, lines[0])
			if mode == "bidi" {
				assert.JSONEq(t, `{"text":"two"}`, lines[1])
			} else {
				assert.JSONEq(t, `{"text":"one"}`, lines[1])
			}
		})
	}
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

func streamingServer(t *testing.T, mode string, secure bool) *httptest.Server {
	t.Helper()
	types := map[string]connect.StreamType{"server": connect.StreamTypeServer, "client": connect.StreamTypeClient, "bidi": connect.StreamTypeBidi}
	service := connect.NewServer()
	service.Register(connect.Method{
		Spec: connect.Spec{Procedure: echoMethod, StreamType: types[mode]},
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			info, _ := connecthttp.ServerInfoForContext(ctx)
			wantProto := "HTTP/1.1"
			if mode == "bidi" || secure {
				wantProto = "HTTP/2.0"
			}
			assert.Equal(t, wantProto, info.RequestProto())
			count := 0
			for {
				var message structpb.Struct
				if err := stream.Receive(&message); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return fmt.Errorf("receive streaming fixture request: %w", err)
				}
				count++
				if mode != "client" {
					if err := stream.Send(&message); err != nil {
						return fmt.Errorf("send fixture response: %w", err)
					}
				}
				if mode == "server" {
					return stream.Send(&message)
				}
			}
			if mode == "client" {
				response := &structpb.Struct{Fields: map[string]*structpb.Value{"count": structpb.NewNumberValue(float64(count))}}
				return stream.Send(response)
			}
			return nil
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service)
	server := httptest.NewUnstartedServer(mux)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	if secure {
		server.EnableHTTP2 = true
		server.Config.Protocols.SetHTTP2(true)
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

func TestExampleCRPCDiscoversAndInvokesWithSchemas(t *testing.T) {
	t.Parallel()
	set := schemaSet(false)
	path := writeProtoset(t, set)
	server, _ := schemaServer(t, set, "")
	for _, source := range [][]string{{"--protoset", path}, {"--reflect"}} {
		output, _, err := run(t, nil, append([]string{"crpc", server.URL, "--list", "example.v1.EchoService"}, source...)...)
		require.NoError(t, err)
		assert.Equal(t, "Echo\n", output)
		output, _, err = run(t, nil, append([]string{"crpc", server.URL, "example.v1.EchoService/Echo", "-d", `{"text":"hello"}`}, source...)...)
		require.NoError(t, err)
		assert.JSONEq(t, `{"text":"hello"}`, output)
	}
	output, _, err := run(t, nil, "crpc", "--protoset", path)
	require.NoError(t, err)
	assert.Equal(t, "example.v1.EchoService\n", output)
	output, _, err = run(t, nil, "crpc", "--protoset", path, "--describe", "example.v1.Request", "--format", "json")
	require.NoError(t, err)
	var description map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &description))
	assert.Equal(t, "Request", description["name"])
}
