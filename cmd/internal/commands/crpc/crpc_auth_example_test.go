package crpc_test

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleCRPCBearerToken(t *testing.T) {
	t.Parallel()
	recorder := &authorizationRecorder{}
	server, caPath := startTLSSchemaServer(t, recorder)
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("example-token\n"), 0o600))

	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--ca", caPath,
		"--auth-bearer-file", tokenPath, "-d", `{"text":"hello"}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"text":"hello"}`, output)
	reflection, call := recorder.split()
	assert.NotEmpty(t, reflection, "reflection requests were recorded")
	for _, values := range append(reflection, call...) {
		assert.Equal(t, []string{"Bearer example-token"}, values)
	}
	assert.Len(t, call, 1)
}

func TestExampleCRPCCleartextAuthRequiresOptIn(t *testing.T) {
	t.Parallel()
	recorder := &authorizationRecorder{}
	server, _ := schemaServer(t, schemaSet(false), "", recorder.intercept)

	_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--auth-bearer", "local-token", "-d", `{}`)
	require.ErrorIs(t, err, errInvalidCRPCFlags, "credentials over http:// need an explicit opt-in")
	reflection, call := recorder.split()
	assert.Empty(t, append(reflection, call...))

	_, _, err = run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--auth-bearer", "local-token",
		"--insecure-cleartext-auth", "-d", `{}`)
	require.NoError(t, err)
	_, call = recorder.split()
	assert.Equal(t, [][]string{{"Bearer local-token"}}, call)
}

// authorizationRecorder keeps each request's Authorization values, split into reflection and application calls.
type authorizationRecorder struct {
	reflection [][]string
	call       [][]string
	mu         sync.Mutex
}

func (recorder *authorizationRecorder) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		info, _ := connect.CallInfoForServerContext(ctx)
		values := info.RequestHeader().Values("Authorization")
		recorder.mu.Lock()
		if strings.HasPrefix(spec.Procedure, "/grpc.reflection.") {
			recorder.reflection = append(recorder.reflection, values)
		} else {
			recorder.call = append(recorder.call, values)
		}
		recorder.mu.Unlock()
		return next(ctx, spec, stream)
	}
}

func (recorder *authorizationRecorder) split() ([][]string, [][]string) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([][]string(nil), recorder.reflection...), append([][]string(nil), recorder.call...)
}

func startTLSSchemaServer(t *testing.T, recorder *authorizationRecorder) (*httptest.Server, string) {
	t.Helper()
	handler, _ := schemaHandler(t, schemaSet(false), "", recorder.intercept)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	return server, caPath
}
