package aes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
)

func TestAESCompletionFiltersConflictingFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		want     string
		unwanted string
		args     []string
	}{
		{name: "CBC hides AAD", args: []string{"aes", "encrypt", "--key", "AA==", "--cipher-mode", "cbc", "--"}, want: "--iv", unwanted: "--aad"},
		{name: "GCM hides IV", args: []string{"aes", "encrypt", "--key", "AA==", "--cipher-mode", "gcm", "--"}, want: "--aad", unwanted: "--iv"},
		{name: "default GCM hides IV", args: []string{"aes", "encrypt", "--key", "AA==", "--"}, want: "--aad", unwanted: "--iv"},
		{name: "empty AAD before mode hides IV", args: []string{"aes", "e", "--key", "AA==", "--aad=", "--"}, want: "--cipher-mode", unwanted: "--iv"},
		{name: "empty IV before mode hides AAD", args: []string{"aes", "enc", "--key", "AA==", "--iv=", "--"}, want: "--cipher-mode", unwanted: "--aad"},
		{
			name:     "last repeated mode wins",
			want:     "--iv",
			unwanted: "--aad",
			args:     []string{"aes", "encrypt", "--key", "AA==", "--cipher-mode", "gcm", "--cipher-mode", "cbc", "--"},
		},
		{name: "decrypt CBC hides AAD", args: []string{"aes", "dec", "--cipher-mode", "cbc", "--"}, want: "--key", unwanted: "--aad"},
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
		{name: "IV", args: []string{"aes", "encrypt", "--cipher-mode", "cbc", "--iv", ""}},
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
