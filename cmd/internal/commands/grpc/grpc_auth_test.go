package grpc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
)

func TestGRPCAuthValidationPrecedesNetwork(t *testing.T) {
	t.Parallel()
	const secret = "validation-secret"
	for _, test := range []struct {
		name  string
		want  string
		flags []string
		stdin bool
	}{
		{name: "two sources", flags: []string{"--auth-bearer", "a", "--auth-bearer-env", "TOKEN"}, want: "choose one of"},
		{name: "Authorization metadata", flags: []string{"--auth-bearer", "a", "-H", "Authorization: x"}, want: "Authorization --header"},
		{name: "plaintext without opt-in", flags: []string{"--plaintext", "--auth-bearer", secret}, want: "without TLS requires"},
		{name: "opt-in without credential", flags: []string{"--plaintext", "--insecure-cleartext-auth"}, want: "requires an --auth-* credential"},
		{name: "plaintext with no-verify", flags: []string{"--plaintext", "--insecure-no-verify", "--auth-bearer", "a"}, want: "--plaintext conflicts"},
		{name: "plaintext umbrella without credential", flags: []string{"--plaintext", "--insecure"}, want: "--plaintext conflicts"},
		{name: "payload owns stdin", flags: []string{"--auth-bearer-file", "-"}, stdin: true, want: "--auth-bearer-file and payload"},
		{name: "malformed token", flags: []string{"--auth-bearer", secret + " extra"}, want: "printable ASCII without whitespace"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			args := []string{"grpc", address, grpcFixtureMethodName}
			if !test.stdin {
				args = append(args, "-d", `{}`)
			}
			input := &countingReader{source: strings.NewReader(`{}`)}
			root := newRootCmd()
			root.SetIn(input)
			_, stderr, err := executeRootCommandStreams(t, root, append(args, test.flags...)...)
			require.ErrorIs(t, err, errInvalidGRPCOptions)
			assert.Contains(t, err.Error(), test.want)
			assert.NotContains(t, err.Error()+stderr, secret, "diagnostics expose the credential")
			assert.Zero(t, input.reads.Load(), "validation read stdin")
			assert.Zero(t, record.connectionCount(), "validation reached the network")
		})
	}
}

func TestGRPCAuthFileCannotBeOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("token\n"), 0o600))
	_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", grpcFixtureMethodName, "-d", `{}`,
		"--auth-bearer-file", path, "--output", path)
	require.ErrorIs(t, err, certinput.ErrPathCollision)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "token\n", string(data), "the credential file was overwritten")
}

func TestGRPCAuthUmbrellaPermitsPlaintextCredential(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`,
		"--plaintext", "--insecure", "--auth-bearer", "local-token")
	require.NoError(t, err)
	_, callMD, _ := record.snapshot()
	assert.Equal(t, []string{"Bearer local-token"}, callMD.Get("authorization"))
}

func TestGRPCAuthCleartextOptInIsInertOverTLS(t *testing.T) {
	t.Parallel()
	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`,
		"--ca", caPath, "--auth-bearer", "t", "--insecure-cleartext-auth")
	require.NoError(t, err)
	_, callMD, _ := record.snapshot()
	assert.Equal(t, []string{"Bearer t"}, callMD.Get("authorization"))
}

func TestGRPCAuthStaysOutOfVerboseDiagnostics(t *testing.T) {
	t.Parallel()
	const secret = "diagnostic-secret"
	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	stdout, stderr, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`,
		"--ca", caPath, "--auth-bearer", secret, "--verbose")
	require.NoError(t, err)
	_, callMD, _ := record.snapshot()
	assert.Equal(t, []string{"Bearer " + secret}, callMD.Get("authorization"))
	assert.NotContains(t, stdout+stderr, secret)
}

func TestGRPCInsecureNoVerify(t *testing.T) {
	t.Parallel()
	address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	for _, flag := range []string{"--insecure", "--insecure-no-verify"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`, flag, "--verbose")
			require.NoError(t, err)
			assert.JSONEq(t, `{}`, stdout)
			requireGRPCTLSFacts(t, stderr, false)

			_, _, err = executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`, flag, "--ca", caPath)
			require.ErrorIs(t, err, errInvalidGRPCOptions)
			assert.Contains(t, err.Error(), flag, "the conflict names the flag the user passed")
		})
	}
}

func TestGRPCCompletionSendsCredentialFlags(t *testing.T) {
	t.Parallel()
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("completion-token\n"), 0o600))

	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	services, _ := completeGRPCCommand(t, address, "--ca", caPath, "--auth-bearer-file", tokenPath, "fixture.v1.E")
	assertGRPCCompletion(t, services, grpcFixtureServiceName+"/")
	_, _, reflectionMD := record.snapshot()
	assert.Equal(t, []string{"Bearer completion-token"}, reflectionMD.Get("authorization"))

	stdinAddress, stdinCAPath, stdinRecord := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	input := &countingReader{source: strings.NewReader("stdin-token\n")}
	root := newRootCmd()
	root.SetIn(input)
	values, _, _ := completeGRPCCommandWithRoot(t, root, stdinAddress, "--ca", stdinCAPath, "--auth-bearer-file", "-", "fixture.v1.E")
	assert.Empty(t, values, "completion cannot read a stdin credential")
	assert.Zero(t, input.reads.Load())
	assert.Zero(t, stdinRecord.connectionCount())

	plainAddress, _, plainRecord := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	values, _ = completeGRPCCommand(t, plainAddress, "--plaintext", "--auth-bearer", "t", "fixture.v1.E")
	assert.Empty(t, values, "completion respects the cleartext opt-in")
	assert.Zero(t, plainRecord.connectionCount())
}

func TestGRPCCompletionCredentialVisibility(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		args           []string
		want, unwanted []string
	}{
		{name: "defaults", args: []string{"--"}, want: []string{"--auth-bearer", "--insecure-no-verify"}, unwanted: []string{"--insecure-cleartext-auth"}},
		{name: "credential shows opt-in", args: []string{"--auth-basic-env", "BASIC", "--"}, want: []string{"--insecure-cleartext-auth"}},
		{name: "Authorization metadata hides credentials", args: []string{"-H", "authorization: x", "--"}, unwanted: []string{"--auth-bearer", "--auth-basic-file"}},
		{name: "plaintext hides no-verify", args: []string{"--plaintext", "--"}, unwanted: []string{"--insecure-no-verify", "--insecure"}},
		{name: "plaintext credential keeps umbrella", args: []string{"--plaintext", "--auth-bearer", "t", "--"}, want: []string{"--insecure"}},
		{name: "no-verify hides trust", args: []string{"--insecure-no-verify", "--"}, unwanted: []string{"--ca", "--system-ca", "--plaintext"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values, _ := completeGRPCCommand(t, append([]string{"127.0.0.1:1"}, test.args...)...)
			for _, want := range test.want {
				assertGRPCCompletion(t, values, want)
			}
			for _, unwanted := range test.unwanted {
				assertNoGRPCCompletion(t, values, unwanted)
			}
		})
	}
}
