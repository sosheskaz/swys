package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExampleGRPCListsServices(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	stdout, stderr, err := executeRootStreams(t, "grpc", address, "--plaintext")
	if err != nil {
		t.Fatalf("npc grpc HOST:PORT --plaintext: %v", err)
	}
	if !strings.Contains(stdout, grpcFixtureServiceName) {
		t.Fatalf("service listing %q does not contain %q", stdout, grpcFixtureServiceName)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}

func TestExampleGRPCInvokesUnaryMethod(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	request := `{"text":"hello","payload":"AAEC","count":"9007199254740993","mode":"MODE_ACTIVE","tags":["a","b"],"labels":{"one":1},"name":"consumer"}`
	stdout, stderr, err := executeRootStreams(t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--data", request,
	)
	if err != nil {
		t.Fatalf("npc grpc HOST:PORT SERVICE/METHOD --data JSON --plaintext: %v", err)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("response is not protobuf JSON: %v; output %q", err, stdout)
	}
	if response["text"] != "hello" || response["payload"] != "AAEC" || response["count"] != "9007199254740993" || response["mode"] != "MODE_ACTIVE" {
		t.Fatalf("response did not preserve protobuf JSON values: %#v", response)
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("response %q does not end with a newline", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}

func TestExampleGRPCDiscoversOfflineFromProtoset(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	stdout, stderr, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", protoset)
	if err != nil {
		t.Fatalf("npc grpc HOST:PORT --protoset FILE: %v", err)
	}
	if !strings.Contains(stdout, grpcFixtureServiceName) {
		t.Fatalf("offline service listing %q does not contain %q", stdout, grpcFixtureServiceName)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}
