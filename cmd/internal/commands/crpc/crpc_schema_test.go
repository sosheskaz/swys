package crpc_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/grpcreflect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCRPCSchemaInfersStreamingAndRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	path := writeProtoset(t, schemaSet(true))
	server := streamingServer(t, "server", false)
	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--protoset", path, "-d", `{"text":"hello"}`)
	require.NoError(t, err)
	assert.Len(t, strings.Split(strings.TrimSpace(output), "\n"), 2)
	for _, extra := range [][]string{{"--stream", "unary"}, {"--format", "json"}, {"-d", `{"unknown":true}`}} {
		args := append([]string{"crpc", server.URL + echoMethod, "--protoset", path}, extra...)
		_, _, err := run(t, nil, args...)
		require.Error(t, err)
	}
}

func schemaSet(streaming bool) *descriptorpb.FileDescriptorSet {
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name: new("echo.proto"), Package: new("example.v1"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Request"), Field: []*descriptorpb.FieldDescriptorProto{{
				Name: new("text"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("EchoService"), Method: []*descriptorpb.MethodDescriptorProto{{
				Name: new("Echo"), InputType: new(".example.v1.Request"), OutputType: new(".example.v1.Request"),
				ServerStreaming: new(streaming),
			}},
		}},
	}}}
}

func writeProtoset(t *testing.T, set *descriptorpb.FileDescriptorSet) string {
	t.Helper()
	data, err := proto.Marshal(set)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "schema.protoset")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func schemaServer(
	t *testing.T, set *descriptorpb.FileDescriptorSet, prefix string, interceptors ...connect.ServerInterceptor,
) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	files, err := protodesc.NewFiles(set)
	require.NoError(t, err)
	methods := &atomic.Int32{}
	service := connect.NewServer(interceptors...)
	service.Register(connect.Method{
		Spec: connect.Spec{Procedure: echoMethod},
		Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			methods.Add(1)
			var request structpb.Struct
			if err := stream.Receive(&request); err != nil {
				return fmt.Errorf("fixture receive: %w", err)
			}
			return stream.Send(&request)
		},
	})
	grpcreflect.Register(service, grpcreflect.WithDescriptorResolver(files),
		grpcreflect.WithNamer(grpcreflect.NamerFunc(func() []string { return []string{"example.v1.EchoService"} })))
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service)
	var handler http.Handler = mux
	if prefix != "" {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.True(t, strings.HasPrefix(r.RequestURI, "/rpc%2Ftenant/"), "escaped route was changed: %s", r.RequestURI)
			r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			r.URL.RawPath = ""
			mux.ServeHTTP(w, r)
		})
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	return server, methods
}

func TestCRPCReflectionVersionFallbackAndScope(t *testing.T) {
	t.Parallel()
	for _, code := range []connect.Code{0, connect.CodeUnimplemented, connect.CodePermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()
			var v1, alpha atomic.Int32
			server, methods := schemaServer(t, schemaSet(false), "/rpc/tenant", func(next connect.ServerFunc) connect.ServerFunc {
				return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
					call, _ := connect.CallInfoForServerContext(ctx)
					assert.Equal(t, "fixture", call.RequestHeader().Get("X-Auth"))
					if strings.HasPrefix(spec.Procedure, "/grpc.reflection.v1.") {
						v1.Add(1)
						if code != 0 {
							return connect.NewError(code, "fixture reflection status")
						}
					}
					if strings.HasPrefix(spec.Procedure, "/grpc.reflection.v1alpha.") {
						alpha.Add(1)
					}
					call.ResponseTrailer().Set("Fixture-Trailer", "complete")
					return next(ctx, spec, stream)
				}
			})
			output, diagnostics, err := run(t, nil, "crpc", server.URL+"/rpc%2Ftenant/", "--list", "example.v1.EchoService", "-H", "X-Auth: fixture", "-v")
			assert.EqualValues(t, 0, methods.Load())
			assert.EqualValues(t, 1, v1.Load())
			if code == connect.CodePermissionDenied {
				require.Error(t, err)
				assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
				assert.Zero(t, alpha.Load(), "only Unimplemented can fall back")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "Echo\n", output)
			assert.Contains(t, diagnostics, "complete")
			if code == connect.CodeUnimplemented {
				assert.EqualValues(t, 1, alpha.Load())
			} else {
				assert.Zero(t, alpha.Load())
			}
		})
	}
}

func TestCRPCExplicitSchemaFailurePreservesOutput(t *testing.T) {
	t.Parallel()
	server, calls := schemaServer(t, schemaSet(false), "")
	path := writeProtoset(t, schemaSet(false))
	output := filepath.Join(t.TempDir(), "response.json")
	require.NoError(t, os.WriteFile(output, []byte("keep"), 0o600))
	for _, flags := range [][]string{
		{"--protoset", path, "-d", `{"unknown":true}`},
		{"--protoset", path, "--stream", "bidi", "-d", `{}`},
		{"--protoset", path, "--reflect"},
		{"--protoset", filepath.Join(t.TempDir(), "absent")},
	} {
		_, _, err := run(t, nil, append([]string{"crpc", server.URL + echoMethod, "-o", output}, flags...)...)
		require.Error(t, err)
		data, err := os.ReadFile(output)
		require.NoError(t, err)
		assert.Equal(t, "keep", string(data))
	}
	assert.Zero(t, calls.Load())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, _, err = run(t, nil, "crpc", "--protoset", path, "-o", path)
	require.Error(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, data, after)
}

func TestCRPCSchemaLimitIsIndependentOfMessageLimit(t *testing.T) {
	t.Parallel()
	server, _ := schemaServer(t, schemaSet(false), "")
	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--max-message-size", "32", "-d", `{"text":"hello"}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"text":"hello"}`, output)
}

func TestCRPCReflectionTimeoutIncludesFinalStatus(t *testing.T) {
	t.Parallel()
	server, _ := schemaServer(t, schemaSet(false), "", func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if err := next(ctx, spec, stream); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}
	})
	output, _, err := run(t, nil, "crpc", server.URL, "--reflection-timeout", "50ms")
	require.Error(t, err)
	assert.Equal(t, connect.CodeDeadlineExceeded, connect.CodeOf(err))
	assert.Empty(t, output, "successful lookup must still finish the reflection stream")
}

func TestCRPCUsesStandardGRPCReflection(t *testing.T) {
	t.Parallel()
	files, err := protodesc.NewFiles(schemaSet(false))
	require.NoError(t, err)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	reflectionv1.RegisterServerReflectionServer(server, reflection.NewServerV1(reflection.ServerOptions{DescriptorResolver: files}))
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); assert.NoError(t, <-stopped) })
	output, _, err := run(t, nil, "crpc", "http://"+listener.Addr().String(), "--describe", "example.v1.Request", "--format", "json")
	require.NoError(t, err)
	assert.Contains(t, output, `"Request"`)
}

func TestCRPCSchemaResolvesAnyFromLocalTypes(t *testing.T) {
	t.Parallel()
	set := schemaSet(false)
	set.File[0].Dependency = []string{"google/protobuf/any.proto"}
	set.File[0].MessageType[0].Field = append(set.File[0].MessageType[0].Field, &descriptorpb.FieldDescriptorProto{
		Name: new("payload"), Number: new(int32(2)), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: new(".google.protobuf.Any"),
	})
	set.File = append(set.File, protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto))
	path := writeProtoset(t, set)
	server := echoServer(t, false, false)
	message := `{"payload":{"@type":"type.googleapis.com/example.v1.Request","text":"inside Any"}}`
	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--protoset", path, "-d", message)
	require.NoError(t, err)
	assert.JSONEq(t, message, output)
}
