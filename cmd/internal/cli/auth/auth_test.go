package auth_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/auth"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
)

var errInvalid = errors.New("invalid test options")

const marker = "marker-secret"

func parseFlags(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool(tlsconfig.InsecureFlagName, false, "")
	cmd.Flags().String(tlsconfig.CAFlagName, "", "")
	auth.AddFlags(cmd, cmd.Flags())
	require.NoError(t, cmd.Flags().Parse(args))
	return cmd.Flags()
}

func writeCredential(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func environment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestValueFormatsCredentials(t *testing.T) {
	t.Parallel()
	env := environment(map[string]string{"TOKEN": "env-token", "BASIC": "svc:env-pass"})
	for _, test := range []struct {
		name  string
		args  func(t *testing.T) []string
		stdin string
		want  string
	}{
		{name: "bearer literal", args: literal("--auth-bearer", "abc.DEF-123_~+/="), want: "Bearer abc.DEF-123_~+/="},
		{name: "bearer file trims LF", args: file("--auth-bearer-file", "file-token\n"), want: "Bearer file-token"},
		{name: "bearer file trims CRLF", args: file("--auth-bearer-file", "file-token\r\n"), want: "Bearer file-token"},
		{name: "bearer stdin", args: literal("--auth-bearer-file", "-"), stdin: "stdin-token\n", want: "Bearer stdin-token"},
		{name: "bearer env is exact", args: literal("--auth-bearer-env", "TOKEN"), want: "Bearer env-token"},
		// RFC 7617 sections 2 and 2.1 test vectors.
		{name: "basic literal", args: literal("--auth-basic", "Aladdin:open sesame"), want: "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
		{name: "basic password colon", args: literal("--auth-basic", "Aladdin:open:sesame"), want: "Basic QWxhZGRpbjpvcGVuOnNlc2FtZQ=="},
		{name: "basic empty password", args: literal("--auth-basic", "api-key:"), want: "Basic YXBpLWtleTo="},
		{name: "basic UTF-8", args: literal("--auth-basic", "test:123£"), want: "Basic dGVzdDoxMjPCow=="},
		{name: "basic file", args: file("--auth-basic-file", "svc:file-pass\n"), want: "Basic c3ZjOmZpbGUtcGFzcw=="},
		{name: "basic env", args: literal("--auth-basic-env", "BASIC"), want: "Basic c3ZjOmVudi1wYXNz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			flags := parseFlags(t, test.args(t)...)
			value, ok, err := auth.Value(t.Context(), strings.NewReader(test.stdin), flags, env, errInvalid)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, test.want, value)
		})
	}

	value, ok, err := auth.Value(t.Context(), strings.NewReader(""), parseFlags(t), env, errInvalid)
	require.NoError(t, err)
	assert.False(t, ok, "no credential flag selects no header")
	assert.Empty(t, value)
}

func TestValueRejectsMalformedCredentialsWithoutEchoing(t *testing.T) {
	t.Parallel()
	env := environment(map[string]string{"EMPTY": "", "SPACED": marker + " "})
	oversized := strings.Repeat("a", auth.MaxBytes) + marker
	for _, test := range []struct {
		want error
		args func(t *testing.T) []string
		name string
	}{
		{name: "empty bearer", args: literal("--auth-bearer", ""), want: errInvalid},
		{name: "bearer scheme included", args: literal("--auth-bearer", "bearer "+marker), want: errInvalid},
		{name: "bearer whitespace", args: literal("--auth-bearer", marker+" more"), want: errInvalid},
		{name: "bearer control", args: literal("--auth-bearer", marker+"\x01"), want: errInvalid},
		{name: "bearer non-ASCII", args: literal("--auth-bearer", marker+"é"), want: errInvalid},
		{name: "bearer oversized", args: literal("--auth-bearer", oversized), want: errInvalid},
		{name: "bearer file second line", args: file("--auth-bearer-file", marker+"\nsecond\n"), want: errInvalid},
		{name: "bearer file only one ending trimmed", args: file("--auth-bearer-file", marker+"\n\n"), want: errInvalid},
		{name: "bearer file oversized", args: file("--auth-bearer-file", oversized), want: artifact.ErrTooLarge},
		{name: "bearer env empty", args: literal("--auth-bearer-env", "EMPTY"), want: errInvalid},
		{name: "bearer env exact bytes", args: literal("--auth-bearer-env", "SPACED"), want: errInvalid},
		{name: "bearer env unset", args: literal("--auth-bearer-env", "UNSET"), want: errInvalid},
		{name: "basic without colon", args: literal("--auth-basic", marker), want: errInvalid},
		{name: "basic empty user", args: literal("--auth-basic", ":"+marker), want: errInvalid},
		{name: "basic control", args: literal("--auth-basic", "user:"+marker+"\x00"), want: errInvalid},
		{name: "basic invalid UTF-8", args: literal("--auth-basic", "user:"+marker+"\xff"), want: errInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			flags := parseFlags(t, test.args(t)...)
			value, ok, err := auth.Value(t.Context(), strings.NewReader(""), flags, env, errInvalid)
			require.ErrorIs(t, err, test.want)
			assert.False(t, ok)
			assert.Empty(t, value)
			assert.NotContains(t, err.Error(), marker, "error exposes the credential")
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		args         []string
		secure       bool
		payloadStdin bool
		wantErr      bool
	}{
		{name: "no credential", secure: false},
		{name: "TLS credential", args: []string{"--auth-bearer", "x"}, secure: true},
		{name: "two sources", args: []string{"--auth-bearer", "x", "--auth-basic-env", "BASIC"}, secure: true, wantErr: true},
		{name: "cleartext refused", args: []string{"--auth-bearer", "x"}, wantErr: true},
		{name: "cleartext carve-out", args: []string{"--auth-basic", "u:p", "--insecure-cleartext-auth"}},
		{name: "cleartext umbrella", args: []string{"--auth-bearer-env", "TOKEN", "--insecure"}},
		{name: "TLS umbrella", args: []string{"--auth-bearer", "x", "--insecure"}, secure: true},
		{name: "carve-out without credential", args: []string{"--insecure-cleartext-auth"}, wantErr: true},
		{name: "carve-out with TLS", args: []string{"--auth-bearer", "x", "--insecure-cleartext-auth"}, secure: true, wantErr: true},
		{name: "carve-out false is inert", args: []string{"--insecure-cleartext-auth=false"}, secure: true},
		{name: "empty file path", args: []string{"--auth-bearer-file", ""}, secure: true, wantErr: true},
		{name: "empty variable name", args: []string{"--auth-basic-env", ""}, secure: true, wantErr: true},
		{name: "stdin file", args: []string{"--auth-bearer-file", "-"}, secure: true},
		{name: "payload stdin conflict", args: []string{"--auth-basic-file", "-"}, secure: true, payloadStdin: true, wantErr: true},
		{name: "TLS stdin conflict", args: []string{"--auth-bearer-file", "-", "--ca", "-"}, secure: true, wantErr: true},
		{name: "dot-dash is a file", args: []string{"--auth-bearer-file", "./-"}, secure: true, payloadStdin: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := auth.Validate(parseFlags(t, test.args...), test.secure, test.payloadStdin, errInvalid)
			if test.wantErr {
				require.ErrorIs(t, err, errInvalid)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestStdinAndHeaderOwnership(t *testing.T) {
	t.Parallel()
	assert.True(t, auth.UsesStdin(parseFlags(t, "--auth-bearer-file", "-")))
	assert.False(t, auth.UsesStdin(parseFlags(t, "--auth-bearer", "-")), "a literal dash is a token, not stdin")
	assert.False(t, auth.UsesStdin(parseFlags(t, "--auth-basic-file", "./-")))

	require.NoError(t, auth.RejectHeader(parseFlags(t), true, errInvalid), "raw headers stay available without a credential flag")
	require.NoError(t, auth.RejectHeader(parseFlags(t, "--auth-bearer", "x"), false, errInvalid))
	err := auth.RejectHeader(parseFlags(t, "--auth-bearer-env", "TOKEN"), true, errInvalid)
	require.ErrorIs(t, err, errInvalid)
	assert.Contains(t, err.Error(), "--auth-bearer-env")
}

func literal(name, value string) func(*testing.T) []string {
	return func(*testing.T) []string { return []string{name, value} }
}

func file(name, content string) func(*testing.T) []string {
	return func(t *testing.T) []string {
		t.Helper()
		return []string{name, writeCredential(t, content)}
	}
}
