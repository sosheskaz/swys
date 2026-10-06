package grpc_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestExampleGRPCListsServices(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	stdout, stderr, err := executeRootStreams(t, "grpc", address, "--plaintext")
	require.NoError(t, err, "swys grpc HOST:PORT --plaintext: %v", err)
	assert.Contains(t, stdout, grpcFixtureServiceName)
	assert.Empty(t, stderr)
}

func TestExampleGRPCInvokesUnaryMethod(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	request := `{"text":"hello","payload":"AAEC","count":"9007199254740993","mode":"MODE_ACTIVE","tags":["a","b"],"labels":{"one":1},"name":"consumer"}`
	stdout, stderr, err := executeRootStreams(t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--data", request,
	)
	require.NoError(t, err, "swys grpc HOST:PORT SERVICE/METHOD --data JSON --plaintext: %v", err)
	var response map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &response), "response is not protobuf JSON: %v; output %q", err, stdout)
	if response["text"] != "hello" || response["payload"] != "AAEC" || response["count"] != "9007199254740993" || response["mode"] != "MODE_ACTIVE" {
		t.Fatalf("response did not preserve protobuf JSON values: %#v", response)
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("response %q does not end with a newline", stdout)
	}
	assert.Empty(t, stderr)
}

func TestExampleGRPCInvokesUnaryMethodAsProtobufText(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	files, _, descriptor := grpcFixtureSchema(t)
	resolver := dynamicpb.NewTypes(files)
	request := `{"text":"hello","payload":"AAEC","count":"9007199254740993",` +
		`"mode":"MODE_ACTIVE","tags":["a","b"],"labels":{"one":1},` +
		`"extra":{"@type":"type.googleapis.com/google.protobuf.StringValue","value":"inside"}}`
	want := dynamicpb.NewMessage(descriptor)
	require.NoError(t, (protojson.UnmarshalOptions{Resolver: resolver}).Unmarshal([]byte(request), want))

	stdout, stderr, err := executeRootStreams(t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--format", "text", "--data", request,
	)
	require.NoError(t, err)
	got := dynamicpb.NewMessage(descriptor)
	require.NoError(t, (prototext.UnmarshalOptions{Resolver: resolver}).Unmarshal([]byte(stdout), got),
		"response is not protobuf text: %q", stdout)
	assert.True(t, proto.Equal(want, got), "protobuf text response = %s", stdout)
	assert.True(t, strings.HasSuffix(stdout, "\n"), "response %q does not end with a newline", stdout)
	assert.Empty(t, stderr)
}

func TestExampleGRPCEncodesCompleteOutput(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "services", args: []string{"grpc", address, "--plaintext"}},
		{name: "methods", args: []string{"grpc", address, "--plaintext", "--list", grpcFixtureServiceName, "--format", "json"}},
		{name: "descriptor", args: []string{"grpc", "127.0.0.1:1", "--protoset", protoset, "--describe", "fixture.v1.EchoRequest"}},
		{name: "unary response", args: []string{"grpc", address, grpcFixtureMethodName, "--plaintext", "--data", `{"text":"hello"}`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plain, plainDiagnostics, err := executeRootStreams(t, test.args...)
			require.NoError(t, err)
			require.Empty(t, plainDiagnostics)

			encodedArgs := append(append([]string(nil), test.args...), "-e", "base64", "--verbose")
			encoded, diagnostics, err := executeRootStreams(t, encodedArgs...)
			require.NoError(t, err)
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			require.NoError(t, err, "encoded stdout = %q", encoded)
			assert.Equal(t, plain, string(decoded), "base64 must cover complete stdout including its newline")
			assert.Contains(t, diagnostics, "gRPC status: OK")
		})
	}
}

func TestExampleGRPCDiscoversOfflineFromProtoset(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	stdout, stderr, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", protoset)
	require.NoError(t, err, "swys grpc HOST:PORT --protoset FILE: %v", err)
	assert.Contains(t, stdout, grpcFixtureServiceName)
	assert.Empty(t, stderr)
}
