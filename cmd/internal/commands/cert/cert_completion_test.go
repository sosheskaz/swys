package cert_test

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
			if directive != want {
				t.Errorf("%s %s subject directive = %v, want %v", command, operation, directive, want)
			}
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
	} {
		args := append([]string{"cert", "create"}, test.args...)
		values, directive := executeCertificateCompletion(t, args...)
		if !completionValuesEqual(values, test.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("completion %q = %q, %v; want %q without files", args, values, directive, test.want)
		}
	}
}

func TestCertificateCompletionPreservesParserErrors(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(t, "cert", "create", "--ca=maybe", "--help")
	if err == nil || strings.Contains(err.Error(), "completion flag") {
		t.Errorf("parser error = %v, want original flag error", err)
	}
}

func TestCertificateCompletionPreservesEmptySliceHelpDefaults(t *testing.T) {
	t.Parallel()
	command := certCommand(t, "create")
	for _, name := range []string{"dns", "ip"} {
		flag := command.Flags().Lookup(name)
		if flag.Value.String() != "[]" {
			t.Errorf("%s value = %q, want unchanged empty slice", name, flag.Value.String())
		}
		values, err := command.Flags().GetStringArray(name)
		require.NoError(t, err, "read %s: %v", name, err)
		if len(values) != 0 {
			t.Errorf("%s values = %q, want empty default", name, values)
		}
	}

	stdout, _, err := executeRootStreams(t, "cert", "create", "--help")
	require.NoError(t, err)
	for _, line := range []string{
		"--dns stringArray         DNS subject alternative name (repeatable)",
		"--ip stringArray          IP subject alternative name (repeatable)",
	} {
		if !strings.Contains(stdout, line) {
			t.Errorf("help missing unchanged flag usage %q:\n%s", line, stdout)
		}
	}
	if strings.Contains(stdout, "(default [])") {
		t.Fatalf("help exposes empty slice implementation default:\n%s", stdout)
	}
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
		if !strings.Contains(joined, text) {
			t.Errorf("day descriptions = %q, missing %q", values, text)
		}
	}
	if certificateCompletionContains(values, "0") {
		t.Errorf("day values include invalid explicit zero: %q", values)
	}
	wantDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
	if directive != wantDirective {
		t.Fatalf("day directive = %v, want %v", directive, wantDirective)
	}

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
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("artifact directive = %v, want explicit paths with no fallback", directive)
	}

	values, directive = executeCertificateCompletion(t, "cert", "create", "--key", subdirectory)
	if !certificateCompletionContains(values, subdirectory+string(filepath.Separator)) {
		t.Fatalf("directory completions = %q, want directory continuation", values)
	}
	wantDirectoryDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if directive != wantDirectoryDirective {
		t.Fatalf("directory directive = %v, want %v", directive, wantDirectoryDirective)
	}

	values, directive = executeCertificateCompletion(t, "cert", "create", "--key", fileWithSpaces)
	if !certificateCompletionContains(values, fileWithSpaces) {
		t.Fatalf("file completions = %q, want terminal file", values)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("file directive = %v, want terminal file completion", directive)
	}

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "create key", args: []string{"cert", "create", "--key", ""}},
		{name: "create issuer certificate", args: []string{"cert", "create", "--issuer-cert", ""}},
		{name: "create issuer key", args: []string{"cert", "create", "--issuer-key", ""}},
		{name: "CSR key", args: []string{"cert", "csr", "--key", ""}},
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
