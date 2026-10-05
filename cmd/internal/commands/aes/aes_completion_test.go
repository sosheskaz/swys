package aes_test

import (
	"bytes"
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
		name, want string
		unwanted   []string
		args       []string
	}{
		{
			name:     "literal key hides keyset selection",
			args:     []string{"aes", "encrypt", "--key-base64", "AA==", "--"},
			want:     "--wire-format",
			unwanted: []string{"--key-id", "--aad"},
		},
		{
			name: "Tink hides OpenPGP key selection", want: "--aad", unwanted: []string{"--key-id"},
			args: []string{"aes", "encrypt", "--key-base64", "AA==", "--wire-format", "tink", "--"},
		},
		{
			name:     "OpenPGP decrypt reads packet chunk size",
			args:     []string{"aes", "decrypt", "--key-base64", "AA==", "--"},
			want:     "--wire-format",
			unwanted: []string{"--chunk-size", "--hkdf-hash"},
		},
		{name: "key hides password costs", args: []string{"aes", "encrypt", "--key-base64", "AA==", "--"}, want: "--chunk-size", unwanted: []string{"--kdf-memory"}},
		{
			name:     "password hides key selection",
			args:     []string{"aes", "encrypt", "--password-env", "NAME", "--"},
			want:     "--kdf-memory",
			unwanted: []string{"--key-id"},
		},
		{
			name:     "raw keygen hides Tink tuning",
			args:     []string{"aes", "keygen", "--"},
			want:     "--bits",
			unwanted: []string{"--chunk-size", "--hkdf-hash", "--derived-key-bits"},
		},
		{
			name: "alias and last wire choice preserve possible keyset selection", want: "--key-id", unwanted: []string{"--aad", "--hkdf-hash"},
			args: []string{"aes", "enc", "--key", filepath.Join(t.TempDir(), "missing-key"), "--wire-format", "tink", "--wire-format", "openpgp", "--"},
		},
		{
			name:     "password decrypt has no chunk tuning",
			args:     []string{"aes", "d", "--password-env", "NAME", "--"},
			want:     "--wire-format",
			unwanted: []string{"--chunk-size"},
		},
		{
			name:     "Tink conversion has no import tuning",
			args:     []string{"aes", "key-convert", "--from", "tink-json", "--to", "raw", "--"},
			want:     "--key-id",
			unwanted: []string{"--chunk-size", "--hkdf-hash", "--derived-key-bits"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			assert.Contains(t, output, test.want)
			for _, flag := range test.unwanted {
				assert.NotContains(t, output, flag)
			}
			assertCompletionDirective(t, output, ":4")
		})
	}
}

func TestAESCompletionConstrainsWireValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, want, unwanted string
		args                 []string
	}{
		{name: "password requires OpenPGP", args: []string{"aes", "encrypt", "--password-env", "NAME", "--wire-format", ""}, want: "openpgp", unwanted: "tink"},
		{name: "AAD requires Tink in reverse order", args: []string{"aes", "encrypt", "--aad", "context", "--wire-format", ""}, want: "tink", unwanted: "openpgp"},
		{
			name:     "HKDF requires Tink in reverse order",
			args:     []string{"aes", "encrypt", "--hkdf-hash", "sha512", "--wire-format", ""},
			want:     "tink",
			unwanted: "openpgp",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			assertCompletionLine(t, output, test.want)
			for _, line := range strings.Split(output, "\n") {
				value, _, _ := strings.Cut(line, "\t")
				assert.NotEqual(t, test.unwanted, value)
			}
			assertCompletionDirective(t, output, ":4")
		})
	}
}

func TestAESCompletionConstrainsValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		args           []string
		want, unwanted []string
	}{
		{name: "password offers only enabled mode", args: []string{"aes", "encrypt", "--password="}, want: []string{"true"}, unwanted: []string{"false"}},
		{
			name:     "Tink wire excludes password mode",
			args:     []string{"aes", "encrypt", "--wire-format", "tink", "--password="},
			unwanted: []string{"true", "false"},
		},
		{
			name:     "selected literal key excludes password mode",
			args:     []string{"aes", "encrypt", "--key-base64", "AA==", "--password="},
			unwanted: []string{"true", "false"},
		},
		{
			name:     "literal key format is raw",
			args:     []string{"aes", "encrypt", "--key-base64", "AA==", "--key-format", ""},
			want:     []string{"raw"},
			unwanted: []string{"auto", "tink-json", "tink-binary"},
		},
		{
			name:     "keygen tuning requires Tink output",
			args:     []string{"aes", "keygen", "--chunk-size", "1MiB", "--key-format", ""},
			want:     []string{"tink-json", "tink-binary"},
			unwanted: []string{"raw"},
		},
		{
			name:     "key selection requires raw target",
			args:     []string{"aes", "key-convert", "--from", "tink-json", "--key-id", "1", "--to", ""},
			want:     []string{"raw"},
			unwanted: []string{"tink-json", "tink-binary"},
		},
		{
			name:     "key selection retains unknown container input",
			args:     []string{"aes", "key-convert", "--key-id", "1", "--to", "raw", "--from", ""},
			want:     []string{"auto", "tink-json", "tink-binary"},
			unwanted: []string{"raw"},
		},
		{
			name:     "derived bits cannot exceed generated key",
			args:     []string{"aes", "keygen", "--key-format", "tink-json", "--bits", "128", "--derived-key-bits", ""},
			want:     []string{"128"},
			unwanted: []string{"256"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			for _, value := range test.want {
				assertCompletionLine(t, output, value)
			}
			for _, line := range strings.Split(output, "\n") {
				value, _, _ := strings.Cut(line, "\t")
				assert.NotContains(t, test.unwanted, value)
			}
			assertCompletionDirective(t, output, ":4")
		})
	}
}

func TestAESCompletionRestoresReferenceHelpWithoutIO(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "output")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	root := rootcmd.NewCommand()
	input := strings.NewReader("operational input")
	before := input.Len()
	output, _, err := testcmd.RunStreams(t, root, input,
		"__complete", "aes", "encrypt", "--password-env", "NPC_AES_COMPLETION_MISSING_PASSWORD",
		"--output", outputPath, "--")
	require.NoError(t, err)
	assert.NotContains(t, string(output), "--key-format", "password completion narrows the interface")
	assert.Equal(t, before, input.Len(), "completion consumed operational stdin")
	contents, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("preserve"), contents, "completion changed operational output")
	command, _, err := root.Find([]string{"aes", "encrypt"})
	require.NoError(t, err)
	var reference bytes.Buffer
	root.SetOut(&reference)
	require.NoError(t, command.Help())
	assert.Contains(t, reference.String(), "--key-format", "reference help must retain the complete interface")
	assert.Contains(t, reference.String(), "--aad", "reference help must retain Tink options")
}

func TestAESCompletionSuppressesFilesForLiteralValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "plaintext", args: []string{"aes", "encrypt", "--key-base64", "AA==", "plain"}},
		{name: "ciphertext", args: []string{"aes", "decrypt", "--key-base64", "AA==", "cipher"}},
		{name: "key", args: []string{"aes", "encrypt", "--key-base64", ""}},
		{name: "AAD", args: []string{"aes", "decrypt", "--aad", ""}},
		{name: "wire format", args: []string{"aes", "encrypt", "--wire-format", ""}},
		{name: "derived key bits", args: []string{"aes", "encrypt", "--wire-format", "tink", "--derived-key-bits", ""}},
		{name: "operation key ID", args: []string{"aes", "encrypt", "--key-format", "tink-json", "--key-id", ""}},
		{name: "keygen chunk size", args: []string{"aes", "keygen", "--key-format", "tink-json", "--chunk-size", ""}},
		{name: "conversion chunk size", args: []string{"aes", "key-convert", "--from", "raw", "--to", "tink-json", "--chunk-size", ""}},
		{name: "conversion key ID", args: []string{"aes", "key-convert", "--from", "tink-json", "--to", "raw", "--key-id", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := completeRoot(t, test.args...)
			assertCompletionDirective(t, output, ":4")
		})
	}

	output := completeRoot(t, "aes", "encrypt", "--key", "")
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
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		if strings.HasPrefix(line, ":") {
			continue
		}
		value, description, described := strings.Cut(line, "\t")
		assert.True(t, described, "candidate %q needs a description", value)
		assert.NotEmpty(t, strings.TrimSpace(description), "candidate %q description", value)
	}
	plain, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "__completeNoDesc", "aes", "keygen", "--bits", "")
	require.NoError(t, err)
	assertCompletionLine(t, string(plain), "128")
	assertCompletionLine(t, string(plain), "256")
	assert.NotContains(t, string(plain), "\t")
	assertCompletionDirective(t, string(plain), ":4")
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
					value, _, _ := strings.Cut(line, "\t")
					require.NotEqual(t, "auto", value)
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
		value, _, _ := strings.Cut(line, "\t")
		if value == want {
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
