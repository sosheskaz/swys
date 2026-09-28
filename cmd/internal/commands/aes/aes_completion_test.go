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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			if !strings.Contains(output, test.want) {
				t.Fatalf("completion %q does not contain %q", output, test.want)
			}
			if strings.Contains(output, test.unwanted) {
				t.Fatalf("completion %q contains conflicting %q", output, test.unwanted)
			}
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
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("aes genkey error = %v, want unknown command", err)
	}
	require.Empty(t, stdout, "aes genkey stdout = %q, want empty", stdout)
	outputPath := filepath.Join(t.TempDir(), "key")
	if _, _, err := executeRootStreams(t, "aes", "genkey", "--output", outputPath); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("aes genkey --output error = %v, want unknown command", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("aes genkey --output file error = %v, want not-exist", err)
	}
	if _, _, err := executeRootStreams(t, "aes", "genkey", "--bits", "256"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("aes genkey --bits error = %v, want removed flag", err)
	}
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
