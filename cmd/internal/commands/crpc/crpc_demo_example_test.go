package crpc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"
)

const elizaService = "connectrpc.eliza.v1.ElizaService"

// TestExampleCRPCDemoWorkflow follows the guide's demo.connectrpc.com workflow
// against a local stand-in, because automated tests do not use public services.
func TestExampleCRPCDemoWorkflow(t *testing.T) {
	t.Parallel()
	server, calls := elizaServer(t)
	dir := t.TempDir()

	services, _, err := run(t, nil, "crpc", server.URL)
	require.NoError(t, err)
	assert.Contains(t, strings.Split(services, "\n"), elizaService)
	methods, _, err := run(t, nil, "crpc", server.URL, "--list", elizaService)
	require.NoError(t, err)
	assert.Equal(t, "Say\nConverse\nIntroduce\n", methods)
	completed, _, err := run(t, nil, "__complete", "crpc", server.URL, elizaService+"/")
	require.NoError(t, err)
	assert.Contains(t, completed, elizaService+"/Introduce\tserver: connectrpc.eliza.v1.IntroduceRequest -> connectrpc.eliza.v1.IntroduceResponse")
	completed, _, err = run(t, nil, "__complete", "crpc", server.URL, elizaService+"/Say", "-d", "")
	require.NoError(t, err)
	assert.Equal(t, []string{`{"sentence":""}` + "\tconnectrpc.eliza.v1.SayRequest", ":4"}, strings.Split(strings.TrimSpace(completed), "\n"))
	assert.Zero(t, calls.Load(), "discovery and completion never invoke methods")

	request := filepath.Join(dir, "request.json")
	_, _, err = run(t, nil, "crpc", server.URL, "--template", elizaService+"/Say", "-o", request)
	require.NoError(t, err)
	template, err := os.ReadFile(request)
	require.NoError(t, err)
	assert.JSONEq(t, `{"sentence":""}`, string(template))
	require.NoError(t, os.WriteFile(request, []byte(`{"sentence":"hello"}`), 0o600))
	reply, _, err := run(t, nil, "crpc", server.URL, elizaService+"/Say", "--reflect", "-i", request)
	require.NoError(t, err)
	assert.JSONEq(t, `{"sentence":"You said: hello"}`, reply)

	introduction, _, err := run(t, nil, "crpc", server.URL+"/"+elizaService+"/Introduce", "--stream", "server", "-d", `{"name":"Ada"}`)
	require.NoError(t, err)
	assertJSONLines(t, []string{`{"sentence":"Hi Ada."}`, `{"sentence":"I'm Eliza."}`}, introduction)

	requests := filepath.Join(dir, "requests.jsonl")
	require.NoError(t, os.WriteFile(requests, []byte("{\"sentence\":\"hello\"}\n{\"sentence\":\"I feel fine\"}\n"), 0o600))
	conversation, _, err := run(t, nil, "crpc", server.URL+"/"+elizaService+"/Converse", "--stream", "bidi", "-i", requests)
	require.NoError(t, err)
	assertJSONLines(t, []string{`{"sentence":"You said: hello"}`, `{"sentence":"You said: I feel fine"}`}, conversation)
}

func assertJSONLines(t *testing.T, want []string, output string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	require.Len(t, lines, len(want), "JSON Lines output %q", output)
	for i, line := range lines {
		assert.JSONEq(t, want[i], line)
	}
}

// elizaServer serves the demo's Eliza service shape: unary Say, bidirectional
// Converse, and server-streaming Introduce, with reflection.
func elizaServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	files, err := protodesc.NewFiles(elizaSchemaSet())
	require.NoError(t, err)
	calls := &atomic.Int32{}
	sentence := func(text string) *structpb.Struct {
		return &structpb.Struct{Fields: map[string]*structpb.Value{"sentence": structpb.NewStringValue(text)}}
	}
	handlers := map[string]connect.Method{
		"Say": {Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			var request structpb.Struct
			if err := stream.Receive(&request); err != nil {
				return fmt.Errorf("receive Say request: %w", err)
			}
			return stream.Send(sentence("You said: " + request.GetFields()["sentence"].GetStringValue()))
		}},
		"Converse": {Spec: connect.Spec{StreamType: connect.StreamTypeBidi}, Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			for {
				var request structpb.Struct
				if err := stream.Receive(&request); errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return fmt.Errorf("receive Converse request: %w", err)
				}
				if err := stream.Send(sentence("You said: " + request.GetFields()["sentence"].GetStringValue())); err != nil {
					return fmt.Errorf("send Converse response: %w", err)
				}
			}
		}},
		"Introduce": {Spec: connect.Spec{StreamType: connect.StreamTypeServer}, Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			var request structpb.Struct
			if err := stream.Receive(&request); err != nil {
				return fmt.Errorf("receive Introduce request: %w", err)
			}
			if err := stream.Send(sentence("Hi " + request.GetFields()["name"].GetStringValue() + ".")); err != nil {
				return fmt.Errorf("send Introduce response: %w", err)
			}
			return stream.Send(sentence("I'm Eliza."))
		}},
	}
	service := connect.NewServer()
	for name, method := range handlers {
		method.Spec.Procedure = "/" + elizaService + "/" + name
		handler := method.Handler
		method.Handler = func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			calls.Add(1)
			return handler(ctx, spec, stream)
		}
		service.Register(method)
	}
	grpcreflect.Register(service, grpcreflect.WithDescriptorResolver(files),
		grpcreflect.WithNamer(grpcreflect.NamerFunc(func() []string { return []string{elizaService} })))
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service)
	return startSchemaServer(t, mux), calls
}

func elizaSchemaSet() *descriptorpb.FileDescriptorSet {
	message := func(name, field string) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{Name: new(name), Field: []*descriptorpb.FieldDescriptorProto{{
			Name: new(field), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
		}}}
	}
	method := func(name string, client, server bool) *descriptorpb.MethodDescriptorProto {
		return &descriptorpb.MethodDescriptorProto{
			Name: new(name), InputType: new(".connectrpc.eliza.v1." + name + "Request"),
			OutputType: new(".connectrpc.eliza.v1." + name + "Response"), ClientStreaming: new(client), ServerStreaming: new(server),
		}
	}
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name: new("connectrpc/eliza/v1/eliza.proto"), Package: new("connectrpc.eliza.v1"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			message("SayRequest", "sentence"), message("SayResponse", "sentence"),
			message("ConverseRequest", "sentence"), message("ConverseResponse", "sentence"),
			message("IntroduceRequest", "name"), message("IntroduceResponse", "sentence"),
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: new("ElizaService"), Method: []*descriptorpb.MethodDescriptorProto{
			method("Say", false, false), method("Converse", true, true), method("Introduce", false, true),
		}}},
	}}}
}
