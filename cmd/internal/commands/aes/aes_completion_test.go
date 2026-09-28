package aes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestAESCompletionFiltersConflictingFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		want     string
		unwanted string
		args     []string
	}{
		{name: "default OpenPGP hides external AAD", args: []string{"aes", "encrypt", "--key", "AA==", "--"}, want: "--key-id", unwanted: "--aad"},
		{
			name: "Tink hides OpenPGP key selection", want: "--aad", unwanted: "--key-id",
			args: []string{"aes", "encrypt", "--key", "AA==", "--wire-format", "tink", "--"},
		},
		{name: "decryption offers wire selection", args: []string{"aes", "decrypt", "--key", "AA==", "--"}, want: "--wire-format", unwanted: "--hkdf-hash"},
		{name: "key hides password costs", args: []string{"aes", "encrypt", "--key", "AA==", "--"}, want: "--chunk-size", unwanted: "--kdf-memory"},
		{name: "password hides key selection", args: []string{"aes", "encrypt", "--password-env", "NAME", "--"}, want: "--kdf-memory", unwanted: "--key-id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			assert.Contains(t, output, test.want)
			assert.NotContains(t, output, test.unwanted)
			assertCompletionDirective(t, output, ":4")
		})
	}
}

func TestAESCompletionSuppressesFilesForLiteralValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "plaintext", args: []string{"aes", "encrypt", "--key", "AA==", "plain"}},
		{name: "ciphertext", args: []string{"aes", "decrypt", "--key", "AA==", "cipher"}},
		{name: "key", args: []string{"aes", "encrypt", "--key", ""}},
		{name: "AAD", args: []string{"aes", "decrypt", "--aad", ""}},
		{name: "wire format", args: []string{"aes", "encrypt", "--wire-format", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			assertCompletionDirective(t, output, ":4")
		})
	}

	output := completeRoot(t, "aes", "encrypt", "--keyfile", "")
	assertCompletionDirective(t, output, ":0")
}

func TestAESGenkeyIsRemoved(t *testing.T) {
	t.Parallel()
	aes, _, err := rootcmd.NewCommand().Find([]string{"aes"})
	require.NoError(t, err)
	for _, command := range aes.Commands() {
		assert.NotEqual(t, "genkey", command.Name(), "aes genkey remains registered")
	}
	stdout, _, err := executeRootStreams(t, "aes", "genkey")
	require.ErrorContains(t, err, "unknown command", "aes genkey")
	require.Empty(t, stdout)
	outputPath := filepath.Join(t.TempDir(), "key")
	_, _, err = executeRootStreams(t, "aes", "genkey", "--output", outputPath)
	require.ErrorContains(t, err, "unknown command", "aes genkey --output")
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("aes genkey --output file error = %v, want not-exist", err)
	}
	_, _, err = executeRootStreams(t, "aes", "genkey", "--bits", "256")
	require.ErrorContains(t, err, "unknown flag", "aes genkey --bits")
}

func TestAESKeygenBitsCompletion(t *testing.T) {
	t.Parallel()
	output := completeRoot(t, "aes", "keygen", "--bits", "")
	assertCompletionLine(t, output, "128")
	assertCompletionLine(t, output, "256")
	assertCompletionDirective(t, output, ":4")
}

func TestAESAutoKeyFormatCompletionOnlyForReaders(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command  string
		flag     string
		wantAuto bool
	}{
		{command: "encrypt", flag: "--key-format", wantAuto: true},
		{command: "decrypt", flag: "--key-format", wantAuto: true},
		{command: "keygen", flag: "--key-format"},
		{command: "key-inspect", flag: "--key-format", wantAuto: true},
		{command: "key-convert", flag: "--from", wantAuto: true},
		{command: "key-convert", flag: "--to"},
	} {
		t.Run(tc.command+"/"+tc.flag, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, "aes", tc.command, tc.flag, "")
			if tc.wantAuto {
				assertCompletionLine(t, output, "auto")
			} else {
				for _, line := range strings.Split(output, "\n") {
					require.NotEqual(t, "auto", line)
				}
			}
			assertCompletionDirective(t, output, ":4")
		})
	}
}

func completeRoot(t *testing.T, args ...string) string {
	t.Helper()
	output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, append([]string{"__complete"}, args...)...)
	require.NoError(t, err)
	return string(output)
}

func assertCompletionLine(t *testing.T, output, want string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if line == want {
			return
		}
	}
	t.Fatalf("completion output %q does not contain line %q", output, want)
}

func assertCompletionDirective(t *testing.T, output, want string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != want {
		t.Fatalf("completion output %q has no directive %q", output, want)
	}
}
