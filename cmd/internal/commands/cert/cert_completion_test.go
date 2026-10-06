package cert_test

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateCompletionSubjectAcrossCreateCSRAndAliases(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"cert", "x509", "certificate", "x.509"} {
		for _, operation := range []string{"create", "csr"} {
			values, directive := executeCertificateCompletion(t, command, operation, "--subject", "CN=")
			if !completionValuesEqual(values, []string{"CN="}) {
				t.Errorf("%s %s subject values = %q, want CN=", command, operation, values)
			}
			want := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
			assert.Equal(t, want, directive, "%s %s subject directive", command, operation)
		}
	}

	values, directive := executeCertificateCompletion(t, "cert", "create", "--subject", "OU=")
	if len(values) != 0 || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("unsupported subject prefix = %q, %v; want no values or files", values, directive)
	}
}

func TestCertificateCompletionRejectsConflictingValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want []string
	}{
		{args: []string{"--ca", "--issuer-cert", ""}},
		{args: []string{"--ca", "--issuer-key="}},
		{args: []string{"--dns", "example.test", "--ca="}, want: []string{"false"}},
		{args: []string{"--ca", "--server-only="}, want: []string{"false"}},
		{args: []string{"--ca", "--client-only="}, want: []string{"false"}},
		{args: []string{"--ca=false", "--server-only="}, want: []string{"true", "false"}},
		{args: []string{"--client-only=false", "--server-only="}},
		{args: []string{"--csr", "request.csr", "--ca="}, want: []string{"false"}},
		{args: []string{"--csr", "request.csr", "--ca", "--ca="}, want: []string{"false"}},
		{args: []string{"--ca", "--ca=false", "--server-only="}, want: []string{"true", "false"}},
	} {
		args := append([]string{"cert", "create"}, test.args...)
		values, directive := executeCertificateCompletion(t, args...)
		if !completionValuesEqual(values, test.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("completion %q = %q, %v; want %q without files", args, values, directive, test.want)
		}
	}
}

func TestCertificateCompletionPreservesReusedRootReferenceHelp(t *testing.T) {
	t.Parallel()
	helpArgs := []string{"cert", "create", "--csr", "missing.csr", "--help"}
	freshHelp, _, err := executeRootStreams(t, helpArgs...)
	require.NoError(t, err)

	root := newRootCmd()
	input := &certVerifyReadCounter{}
	root.SetIn(input)
	_, _, err = executeRootCommandStreams(t, root, "__complete", "cert", "create", "--csr", "missing.csr", "--")
	require.NoError(t, err)
	reusedHelp, _, err := executeRootCommandStreams(t, root, helpArgs...)
	require.NoError(t, err)
	assert.Equal(t, freshHelp, reusedHelp, "completion must preserve the full reference help on later executions")
	assert.Zero(t, input.count.Load(), "completion and reference help must not read payload input")
}

func TestCertificateCompletionPreservesParserErrors(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(t, "cert", "create", "--ca=maybe", "--help")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "completion flag", "want original flag error")
}

func TestCertificateCompletionPreservesEmptySliceHelpDefaults(t *testing.T) {
	t.Parallel()
	command := certCommand(t, "create")
	for _, name := range []string{"dns", "ip"} {
		flag := command.Flags().Lookup(name)
		assert.Equal(t, "[]", flag.Value.String(), "%s unchanged empty slice", name)
		values, err := command.Flags().GetStringArray(name)
		require.NoError(t, err, "read %s: %v", name, err)
		assert.Empty(t, values, "%s empty default", name)
	}

	stdout, _, err := executeRootStreams(t, "cert", "create", "--help")
	require.NoError(t, err)
	helpLines := strings.Split(stdout, "\n")
	for index, line := range helpLines {
		helpLines[index] = strings.Join(strings.Fields(line), " ")
	}
	for _, line := range []string{
		"--dns stringArray DNS subject alternative name (repeatable)",
		"--ip stringArray IP subject alternative name (repeatable)",
	} {
		assert.Contains(t, helpLines, line, "help missing unchanged flag usage")
	}
	assert.NotContains(t, stdout, "(default [])", "help exposes empty slice implementation default")
}

func TestCertificateCompletionDaysHaveDescriptions(t *testing.T) {
	t.Parallel()

	values, directive := executeCertificateCompletion(t, "cert", "create", "--days", "")
	wantValues := []string{"1", "7", "30", "90", "365"}
	if !completionValuesEqual(values, wantValues) {
		t.Fatalf("day values = %q, want %q", values, wantValues)
	}
	joined := strings.Join(values, "\n")
	for _, text := range []string{"default for leaf certificates", "default for certificate authorities"} {
		assert.Contains(t, joined, text, "day descriptions = %q", values)
	}
	assert.False(t, certificateCompletionContains(values, "0"), "day values include invalid explicit zero: %q", values)
	wantDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
	assert.Equal(t, wantDirective, directive, "day directive")

	values, directive = executeCertificateCompletion(t, "cert", "create", "--days", "42")
	if len(values) != 0 || directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Fatalf("custom day completion = %q, %v; want accepted manual value without files", values, directive)
	}
}

func TestCertificateArtifactCompletionOffersFilesAndOneStdinOwner(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	fileWithSpaces := filepath.Join(directory, "issuer key.pem")
	require.NoError(t, os.WriteFile(fileWithSpaces, []byte("must not be parsed during completion"), 0))
	subdirectory := filepath.Join(directory, "issuer directory")
	require.NoError(t, os.Mkdir(subdirectory, 0o700))
	prefix := filepath.Join(directory, "issuer")

	values, directive := executeCertificateCompletion(t, "cert", "create", "--key", prefix)
	if !certificateCompletionContains(values, fileWithSpaces) || !certificateCompletionContains(values, subdirectory+string(filepath.Separator)) {
		t.Fatalf("artifact completions = %q, want spaced file and directory", values)
	}
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "artifact directive: want explicit paths with no fallback")

	values, directive = executeCertificateCompletion(t, "cert", "create", "--key", subdirectory)
	if !certificateCompletionContains(values, subdirectory+string(filepath.Separator)) {
		t.Fatalf("directory completions = %q, want directory continuation", values)
	}
	wantDirectoryDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	assert.Equal(t, wantDirectoryDirective, directive, "directory directive")

	values, directive = executeCertificateCompletion(t, "cert", "create", "--key", fileWithSpaces)
	if !certificateCompletionContains(values, fileWithSpaces) {
		t.Fatalf("file completions = %q, want terminal file", values)
	}
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "want terminal file completion")

	for _, args := range [][]string{
		{"cert", "create", "--csr", "missing.csr", "--key", prefix},
		{"cert", "create", "--key", fileWithSpaces, "--csr", prefix},
	} {
		candidates, pathDirective := executeCertificateCompletion(t, args...)
		assert.Empty(t, candidates, "incompatible artifact values for %q", args)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, pathDirective, "incompatible artifacts must not fall back to files")
	}
	for _, args := range [][]string{
		{"cert", "create", "--ca", "--ca=false", "--csr", prefix},
		{"cert", "create", "--csr", "missing.csr", "--csr", "", "--key", prefix},
	} {
		candidates, pathDirective := executeCertificateCompletion(t, args...)
		assert.True(t, certificateCompletionContains(candidates, fileWithSpaces), "effective values permit artifact paths for %q: %q", args, candidates)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, pathDirective)
	}

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "create key", args: []string{"cert", "create", "--key", ""}},
		{name: "create issuer certificate", args: []string{"cert", "create", "--issuer-cert", ""}},
		{name: "create issuer key", args: []string{"cert", "create", "--issuer-key", ""}},
		{name: "CSR key", args: []string{"cert", "csr", "--key", ""}},
		{name: "verify intermediate", args: []string{"cert", "verify", "--input", "chain.pem", "--intermediates", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _ := executeCertificateCompletion(t, test.args...)
			if !certificateCompletionContains(got, "-") {
				t.Fatalf("completions = %q, want stdin", got)
			}
		})
	}

	for _, args := range [][]string{
		{"cert", "create", "--key", "-", "--issuer-cert", ""},
		{"cert", "create", "--issuer-cert", "-", "--issuer-key", ""},
		{"cert", "create", "--issuer-key", "-", "--key", ""},
		{"cert", "verify", "--intermediates", ""},
		{"cert", "verify", "--input", "chain.pem", "--ca", "-", "--intermediates", ""},
		{"cert", "verify", "--input", "chain.pem", "--intermediates", "-", "--ca", ""},
	} {
		got, _ := executeCertificateCompletion(t, args...)
		if certificateCompletionContains(got, "-") {
			t.Errorf("completion %q = %q, unexpectedly offers a second stdin owner", args, got)
		}
	}
}

func TestCertificateCompletionFiltersCAModeConflictsByEffectiveValue(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"cert", "create", "--key", "key.pem", "--ca", "--"},
		{"cert", "create", "--key", "key.pem", "--ca=true", "--"},
	} {
		values, _ := executeCertificateCompletion(t, args...)
		for _, hidden := range []string{"--dns", "--ip", "--issuer-cert", "--issuer-key", "--server-only", "--client-only"} {
			if completionContainsFlag(values, hidden) {
				t.Errorf("completion %q contains CA conflict %s: %q", args, hidden, values)
			}
		}
	}

	for _, conflict := range [][]string{
		{"--dns", "example.test"},
		{"--ip", "192.0.2.1"},
		{"--issuer-cert", "issuer.crt"},
		{"--issuer-key", "issuer.key"},
		{"--server-only"},
		{"--client-only"},
	} {
		args := append([]string{"cert", "create", "--key", "key.pem"}, conflict...)
		args = append(args, "--")
		values, _ := executeCertificateCompletion(t, args...)
		if completionContainsFlag(values, "--ca") {
			t.Errorf("completion after %q contains --ca: %q", conflict, values)
		}
	}

	for _, falseFlag := range []string{"--ca=false", "--server-only=false", "--client-only=false"} {
		values, _ := executeCertificateCompletion(t, "cert", "create", "--key", "key.pem", falseFlag, "--")
		if falseFlag != "--ca=false" && !completionContainsFlag(values, "--ca") {
			t.Errorf("completion after %s hides --ca: %q", falseFlag, values)
		}
		if falseFlag == "--ca=false" {
			for _, compatible := range []string{"--dns", "--ip", "--issuer-cert", "--server-only"} {
				if !completionContainsFlag(values, compatible) {
					t.Errorf("completion after false CA hides %s: %q", compatible, values)
				}
			}
		}
	}
}

func TestCertificateCompletionSuppressesNonPathFilenameFallback(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"cert", "create", "--subject", ""},
		{"cert", "create", "--dns", ""},
		{"cert", "create", "--ip", ""},
		{"cert", "create", "--days", ""},
		{"cert", "create", "--key", "key.pem", ""},
		{"cert", "csr", "--key", "key.pem", ""},
		{"cert", "inspect", ""},
		{"cert", "verify", ""},
		{"cert", "match", ""},
		{"cert", "verify", "--hostname", ""},
		{"cert", "verify", "--at", ""},
		{"cert", "connect", ""},
		{"cert", "c", ""},
		{"cert", "conn", ""},
		{"cert", "connect", "localhost:443", ""},
	} {
		_, directive := executeCertificateCompletion(t, args...)
		if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
			t.Errorf("completion %q directive = %v, want no filename fallback", args, directive)
		}
	}

	for _, args := range [][]string{
		{"cert", "inspect", "--input", ""},
		{"cert", "create", "--output", ""},
	} {
		_, directive := executeCertificateCompletion(t, args...)
		if directive != cobra.ShellCompDirectiveDefault {
			t.Errorf("path completion %q directive = %v, want default files", args, directive)
		}
	}
}

func executeCertificateCompletion(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	stdout, _, err := executeRootCommandStreams(t, newRootCmd(), append([]string{"__complete"}, args...)...)
	require.NoError(t, err, "complete %q: %v", args, err)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("completion output = %q, want directive", stdout)
	}
	directive, err := strconv.Atoi(strings.TrimPrefix(lines[len(lines)-1], ":"))
	require.NoError(t, err, "parse completion directive: %v", err)
	return lines[:len(lines)-1], cobra.ShellCompDirective(directive)
}

func completionValuesEqual(values, want []string) bool {
	plain := make([]string, len(values))
	for index, value := range values {
		plain[index] = strings.SplitN(value, "\t", 2)[0]
	}
	return slices.Equal(plain, want)
}

func certificateCompletionContains(values []string, want string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		return strings.SplitN(value, "\t", 2)[0] == want
	})
}

func completionContainsFlag(values []string, want string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		return strings.SplitN(value, "\t", 2)[0] == want
	})
}

func TestCertKeygenCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want      string
		args      []string
		directive cobra.ShellCompDirective
	}{
		{args: []string{"cert", "keygen", "--algorithm", ""}, want: "ed25519\tEd25519 signing key", directive: cobra.ShellCompDirectiveNoFileComp},
		{args: []string{"cert", "keygen", "--algorithm", ""}, want: "ecdsa-p256\tECDSA key on NIST P-256", directive: cobra.ShellCompDirectiveNoFileComp},
		{args: []string{"cert", "keygen", "--public-format", ""}, want: "openssh\tOpenSSH public key", directive: cobra.ShellCompDirectiveNoFileComp},
		{args: []string{"cert", "keygen", "--public-out", ""}, directive: cobra.ShellCompDirectiveDefault},
		{args: []string{"cert", "keygen", ""}, directive: cobra.ShellCompDirectiveNoFileComp},
	} {
		values, directive := executeCertificateCompletion(t, test.args...)
		require.Equal(t, test.directive, directive, "completion %v", test.args)
		if test.want != "" {
			require.Contains(t, values, test.want, "completion %v", test.args)
		}
	}
}

func TestCertificateArtifactEncodingCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		operation string
		source    string
	}{
		{operation: "create", source: "key"},
		{operation: "create", source: "csr"},
		{operation: "create", source: "issuer-cert"},
		{operation: "create", source: "issuer-key"},
		{operation: "csr", source: "key"},
		{operation: "match", source: "cert"},
		{operation: "match", source: "key"},
		{operation: "match", source: "csr"},
		{operation: "verify", source: "ca"},
		{operation: "verify", source: "intermediates"},
	} {
		t.Run(test.operation+"/"+test.source, func(t *testing.T) {
			t.Parallel()
			values, directive := executeCertificateCompletion(t, "cert", test.operation,
				"--"+test.source, "missing-artifact", "--"+test.source+"-encoding", "b")
			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
			assert.Len(t, values, 4)
			for _, name := range []string{"b64", "base64", "base64url", "base32"} {
				assert.True(t, certificateCompletionContains(values, name), "missing %s in %q", name, values)
			}
			for _, value := range values {
				parts := strings.SplitN(value, "\t", 2)
				require.Len(t, parts, 2, "encoding completion needs a description: %q", value)
				assert.NotEmpty(t, parts[1])
			}
		})
	}
}

func TestCertificateCompletionHidesInapplicableArtifactEncodings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		flag string
		args []string
	}{
		{args: []string{"cert", "create"}, flag: "key-encoding"},
		{args: []string{"cert", "csr"}, flag: "key-encoding"},
		{args: []string{"cert", "match", "--cert", "missing.pem"}, flag: "csr-encoding"},
		{args: []string{"cert", "verify"}, flag: "ca-encoding"},
		{args: []string{"cert", "verify", "--intermediates="}, flag: "intermediates-encoding"},
		{args: []string{"cert", "create", "--ca", "--issuer-cert", "missing.pem"}, flag: "issuer-cert-encoding"},
		{args: []string{"cert", "create", "--csr", "missing.csr", "--key", "missing.key"}, flag: "key-encoding"},
		{args: []string{"cert", "create", "--key", "-", "--input-encoding", "base64"}, flag: "key-encoding"},
		{args: []string{"cert", "create", "--key", "-", "--key-encoding", "raw"}, flag: "input-encoding"},
	} {
		values, _ := executeCertificateCompletion(t, append(slices.Clone(test.args), "--")...)
		assert.False(t, completionContainsFlag(values, "--"+test.flag), "inapplicable companion for %q: %q", test.args, values)
		values, directive := executeCertificateCompletion(t, append(slices.Clone(test.args), "--"+test.flag, "")...)
		assert.Empty(t, values, "typed inapplicable companion for %q", test.args)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	}
	values, _ := executeCertificateCompletion(t, "cert", "create", "--key", "missing.key", "--")
	assert.True(t, completionContainsFlag(values, "--key-encoding"), "applicable companion must remain visible")
	assert.False(t, completionContainsFlag(values, "--ca-encoding"), "create --ca is a boolean mode")
	independent := []string{
		"cert", "create", "--key", "missing.key", "--issuer-cert", "-",
		"--issuer-key", "missing-issuer.key", "--input-encoding", "base64",
	}
	values, _ = executeCertificateCompletion(t, append(slices.Clone(independent), "--")...)
	assert.True(t, completionContainsFlag(values, "--key-encoding"), "independent named-file codec must remain visible")
	values, directive := executeCertificateCompletion(t, append(independent, "--key-encoding", "b")...)
	assert.Len(t, values, 4, "independent named-file codec must retain encoding suggestions")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	source := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(source, []byte("not parsed during completion"), 0o600))
	values, directive = executeCertificateCompletion(t, "cert", "verify", "--input", "chain.pem", "--intermediates", source)
	if directive == cobra.ShellCompDirectiveDefault {
		return // Cobra filename completion may delegate enumeration to the shell.
	}
	assert.True(t, certificateCompletionContains(values, source), "source paths must remain completable")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}
