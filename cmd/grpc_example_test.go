package cmd

import (
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
