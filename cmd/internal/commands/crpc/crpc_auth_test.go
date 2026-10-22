package crpc_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	crpccommand "github.com/sosheskaz/swys/cmd/internal/commands/crpc"
)

var errInvalidCRPCFlags = crpccommand.ErrInvalidFlags

func TestCRPCAuthValidationPrecedesNetwork(t *testing.T) {
	t.Parallel()
	const secret = "validation-secret"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	protoset := writeProtoset(t, schemaSet(false))
	for _, test := range []struct {
		name  string
		want  string
		args  []string
		stdin bool
	}{
		{name: "two sources", args: []string{"--auth-bearer", "a", "--auth-basic", "u:p", "--insecure"}, want: "choose one of"},
		{name: "Authorization header", args: []string{"--auth-bearer", "a", "--insecure", "-H", "authorization:"}, want: "Authorization --header"},
		{name: "cleartext without opt-in", args: []string{"--auth-bearer", secret}, want: "without TLS requires"},
		{name: "payload owns stdin", args: []string{"--auth-basic-file", "-", "--insecure", "--stdin", "always"}, stdin: true, want: "--auth-basic-file and payload"},
		{name: "malformed credential", args: []string{"--auth-basic", secret, "--insecure"}, want: "requires USER:PASSWORD"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserved"), 0o600))
			args := append([]string{"crpc", server.URL + echoMethod, "--protoset", protoset, "--output", output}, test.args...)
			if !test.stdin {
				args = append(args, "-d", `{}`)
			}
			_, diagnostics, err := run(t, &unexpectedInput{t: t}, args...)
			require.ErrorIs(t, err, errInvalidCRPCFlags)
			assert.Contains(t, err.Error(), test.want)
			assert.NotContains(t, err.Error()+diagnostics, secret, "diagnostics expose the credential")
			data, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, "preserved", string(data))
			assert.Zero(t, requests.Load(), "validation reached the network")
		})
	}

	t.Run("local discovery", func(t *testing.T) {
		t.Parallel()
		_, _, err := run(t, &unexpectedInput{t: t}, "crpc", "--protoset", protoset, "--list", "example.v1.EchoService", "--auth-bearer", "a")
		require.ErrorIs(t, err, errInvalidCRPCFlags)
		assert.Contains(t, err.Error(), "--auth-bearer requires a remote target")
	})
}

func TestCRPCAuthFileCannotBeOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("token\n"), 0o600))
	_, _, err := run(t, nil, "crpc", "https://127.0.0.1:1"+echoMethod, "--auth-bearer-file", path, "--output", path, "-d", `{}`)
	require.ErrorIs(t, err, certinput.ErrPathCollision)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "token\n", string(data), "the credential file was overwritten")
}

func TestCRPCAuthUmbrellaPermitsCleartextCredential(t *testing.T) {
	t.Parallel()
	recorder := &authorizationRecorder{}
	server, _ := schemaServer(t, schemaSet(false), "", recorder.intercept)
	_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--insecure", "--auth-basic", "user:pass", "-d", `{}`)
	require.NoError(t, err)
	_, call := recorder.split()
	assert.Equal(t, [][]string{{"Basic dXNlcjpwYXNz"}}, call)
}

func TestCRPCInsecureFlagsAreInertOverCleartext(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--insecure-cleartext-auth", "--insecure-no-verify", "--insecure"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			recorder := &authorizationRecorder{}
			server, _ := schemaServer(t, schemaSet(false), "", recorder.intercept)
			_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", flag, "-d", `{}`)
			require.NoError(t, err)
			_, call := recorder.split()
			assert.Equal(t, [][]string{nil}, call, "no credential is sent")
		})
	}
}

func TestCRPCAuthCleartextOptInIsInertOverTLS(t *testing.T) {
	t.Parallel()
	recorder := &authorizationRecorder{}
	server, caPath := startTLSSchemaServer(t, recorder)
	_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--ca", caPath,
		"--auth-bearer", "t", "--insecure-cleartext-auth", "-d", `{}`)
	require.NoError(t, err)
	_, call := recorder.split()
	assert.Equal(t, [][]string{{"Bearer t"}}, call)
}

func TestCRPCAuthStaysOutOfVerboseDiagnostics(t *testing.T) {
	t.Parallel()
	const secret = "diagnostic-secret"
	recorder := &authorizationRecorder{}
	server, caPath := startTLSSchemaServer(t, recorder)
	output, diagnostics, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "--ca", caPath,
		"--auth-bearer", secret, "-d", `{}`, "-v")
	require.NoError(t, err)
	_, call := recorder.split()
	assert.Equal(t, [][]string{{"Bearer " + secret}}, call)
	assert.NotContains(t, output+diagnostics, secret)
}

func TestCRPCInsecureNoVerify(t *testing.T) {
	t.Parallel()
	server, caPath := startTLSSchemaServer(t, &authorizationRecorder{})
	_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", "-d", `{}`)
	require.Error(t, err, "an untrusted certificate fails without an insecure flag")
	for _, flag := range []string{"--insecure", "--insecure-no-verify"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			output, diagnostics, err := run(t, nil, "crpc", server.URL+echoMethod, "--reflect", flag, "-d", `{"text":"hi"}`, "-v")
			require.NoError(t, err)
			assert.JSONEq(t, `{"text":"hi"}`, output)
			assert.Contains(t, diagnostics, "verified=false (verify TLS peer: ", "diagnostics explain the tolerated failure")

			_, diagnostics, err = run(t, nil, "crpc", server.URL+echoMethod, "--reflect", flag, "--ca", caPath, "-d", `{}`, "-v")
			require.NoError(t, err, "trust flags combine with %s", flag)
			assert.Contains(t, diagnostics, "verified=true")
			assert.NotContains(t, diagnostics, "verified=false")
		})
	}
}

func TestCRPCCompletionSendsCredentialFlags(t *testing.T) {
	t.Parallel()
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("completion-token\n"), 0o600))
	recorder := &authorizationRecorder{}
	server, caPath := startTLSSchemaServer(t, recorder)
	output, _, err := run(t, nil, "__complete", "crpc", server.URL, "--ca", caPath, "--auth-bearer-file", tokenPath, "example.v1.EchoService/E")
	require.NoError(t, err)
	assert.Contains(t, output, "example.v1.EchoService/Echo")
	reflection, call := recorder.split()
	require.NotEmpty(t, reflection)
	for _, values := range reflection {
		assert.Equal(t, []string{"Bearer completion-token"}, values)
	}
	assert.Empty(t, call, "completion invoked the method")

	for name, args := range map[string][]string{
		"stdin credential":         {"--ca", caPath, "--auth-bearer-file", "-"},
		"cleartext without opt-in": {"--auth-bearer", "t"},
	} {
		quiet := &authorizationRecorder{}
		target, _ := schemaServer(t, schemaSet(false), "", quiet.intercept)
		if name == "stdin credential" {
			target, _ = startTLSSchemaServer(t, quiet)
		}
		quietOutput, _, quietErr := run(t, &unexpectedInput{t: t},
			append(append([]string{"__complete", "crpc", target.URL}, args...), "example.v1.EchoService/E")...)
		require.NoError(t, quietErr, name)
		assert.NotContains(t, quietOutput, "example.v1.EchoService/Echo", name)
		quietReflection, _ := quiet.split()
		assert.Empty(t, quietReflection, "%s reached the server", name)
	}
}

func TestCRPCCompletionCredentialVisibility(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		args           []string
		want, unwanted []string
	}{
		{
			name: "TLS defaults", args: []string{"https://example.test", "--"},
			want: []string{"--auth-bearer", "--insecure", "--insecure-no-verify"}, unwanted: []string{"--insecure-cleartext-auth"},
		},
		{name: "cleartext hides verification", args: []string{"http://example.test", "--"}, unwanted: []string{"--insecure", "--insecure-no-verify"}},
		{
			name: "cleartext credential keeps umbrella", args: []string{"http://example.test", "--auth-bearer", "t", "--"},
			want: []string{"--insecure", "--insecure-cleartext-auth"}, unwanted: []string{"--insecure-no-verify"},
		},
		{
			name: "Authorization header hides credentials", args: []string{"https://example.test", "-H", "Authorization: x", "--"},
			unwanted: []string{"--auth-bearer", "--auth-basic-env"},
		},
		{
			name: "no-verify hides trust roots", args: []string{"https://example.test", "--insecure-no-verify", "--"},
			want: []string{"--cert", "--servername"}, unwanted: []string{"--ca", "--system-ca"},
		},
		{
			name: "CA hides verification carve-outs", args: []string{"https://example.test", "--ca", "unread-ca.pem", "--"},
			want: []string{"--system-ca", "--cert"}, unwanted: []string{"--insecure", "--insecure-no-verify"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, _, err := run(t, nil, append([]string{"__complete", "crpc"}, test.args...)...)
			require.NoError(t, err)
			candidates := map[string]bool{}
			for _, line := range strings.Split(output, "\n") {
				candidate, _, _ := strings.Cut(line, "\t")
				candidates[candidate] = true
			}
			for _, want := range test.want {
				assert.True(t, candidates[want], "completion missing %s", want)
			}
			for _, unwanted := range test.unwanted {
				assert.False(t, candidates[unwanted], "completion unexpectedly offers %s", unwanted)
			}
		})
	}
}
