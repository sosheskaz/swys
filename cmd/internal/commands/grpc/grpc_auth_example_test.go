package grpc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestExampleGRPCBearerToken(t *testing.T) {
	t.Parallel()
	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("example-token\n"), 0o600))

	stdout, stderr, err := executeRootStreams(t,
		"grpc", address, grpcFixtureMethodName, "--ca", caPath, "-d", `{}`, "--auth-bearer-file", tokenPath)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, stdout)
	assert.Empty(t, stderr)
	_, callMD, reflectionMD := record.snapshot()
	for label, md := range map[string]metadata.MD{"call": callMD, "reflection": reflectionMD} {
		assert.Equal(t, []string{"Bearer example-token"}, md.Get("authorization"), "%s metadata", label)
	}
}

func TestExampleGRPCPlaintextAuthRequiresOptIn(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)

	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`,
		"--auth-basic", "local:pass")
	require.ErrorIs(t, err, errInvalidGRPCOptions, "credentials over --plaintext need an explicit opt-in")
	assert.Zero(t, record.connectionCount())

	_, _, err = executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`,
		"--auth-basic", "local:pass", "--insecure-cleartext-auth")
	require.NoError(t, err)
	_, callMD, _ := record.snapshot()
	assert.Equal(t, []string{"Basic bG9jYWw6cGFzcw=="}, callMD.Get("authorization"))
}
