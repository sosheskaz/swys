package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

const (
	testAESKeyBase64        = "AAECAwQFBgcICQoLDA0ODw=="
	testCBCIVBase64         = "EBESExQVFhcYGRobHB0eHw=="
	testCBCPlaintext        = "NPC AES-CBC compatibility fixture"
	testCBCCiphertextHex    = "101112131415161718191a1b1c1d1e1feb98dca3cec8355c01355a5efd0497ac2982948d8e2027237af387ed301652c64da5a753179be260a2bc666a3fbd8080"
	testPreservedOutput     = "preserve this output"
	testGCMMaximumPlaintext = 64 * 1024 * 1024
)

func TestAESCipherModeFlagRegistryHelpAndCompletion(t *testing.T) {
	for _, command := range []*cobra.Command{encryptCmd, decryptCmd} {
		flag := command.Flags().Lookup("cipher-mode")
		if flag == nil {
			t.Fatalf("%s has no --cipher-mode flag", command.CommandPath())
		}
		if flag.DefValue != "gcm" {
			t.Fatalf("%s --cipher-mode default = %q, want gcm", command.CommandPath(), flag.DefValue)
		}
		if flag.Shorthand != "" || flag.NoOptDefVal != "" {
			t.Fatalf("%s --cipher-mode shorthand/no-option = %q/%q, want neither", command.CommandPath(), flag.Shorthand, flag.NoOptDefVal)
		}
		if !strings.Contains(flag.Usage, "cbc, gcm") {
			t.Fatalf("%s --cipher-mode usage = %q, want exact sorted registry", command.CommandPath(), flag.Usage)
		}
		completion, ok := command.GetFlagCompletionFunc("cipher-mode")
		if !ok {
			t.Fatalf("%s --cipher-mode has no completion", command.CommandPath())
		}
		values, directive := completion(command, nil, "")
		if !slices.Equal(values, []string{"cbc", "gcm"}) {
			t.Fatalf("%s --cipher-mode completions = %q, want [cbc gcm]", command.CommandPath(), values)
		}
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Fatalf("%s --cipher-mode completion directive = %v, want no-file", command.CommandPath(), directive)
		}
		aadFlag := command.Flags().Lookup("aad")
		if aadFlag == nil {
			t.Fatalf("%s has no --aad flag", command.CommandPath())
		}
		if aadFlag.DefValue != "" || aadFlag.Shorthand != "" || aadFlag.NoOptDefVal != "" {
			t.Fatalf(
				"%s --aad default/shorthand/no-option = %q/%q/%q, want empty and explicit value",
				command.CommandPath(), aadFlag.DefValue, aadFlag.Shorthand, aadFlag.NoOptDefVal,
			)
		}
	}

	for _, leaf := range []string{"encrypt", "decrypt"} {
		first, err := executeRoot(t, "aes", leaf, "--help")
		if err != nil {
			t.Fatal(err)
		}
		second, err := executeRoot(t, "aes", leaf, "--help")
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatalf("aes %s help changed across identical executions", leaf)
		}
		if !strings.Contains(first, "cbc, gcm") || !strings.Contains(first, `(default "gcm")`) {
			t.Fatalf("aes %s help does not expose sorted modes and GCM default:\n%s", leaf, first)
		}
	}
}

func TestAESCipherModeRejectsNonRegistrySpellingsWithoutTruncation(t *testing.T) {
	for _, leaf := range []string{"encrypt", "decrypt"} {
		for _, mode := range []string{"", "GCM", "CBC", "g", "c"} {
			t.Run(leaf+"_"+modeName(mode), func(t *testing.T) {
				args := []string{"aes", leaf, "--key", testAESKeyBase64, "--cipher-mode=" + mode}
				if leaf == "encrypt" {
					args = append(args, "plaintext")
				}
				assertAESValidationPreservesOutput(t, args, errUnknownAESCipherMode)
			})
		}
	}
}

func TestAESFlagApplicabilityAndValidationPreserveOutput(t *testing.T) {
	tests := []struct {
		wantErr error
		name    string
		args    []string
	}{
		{
			name:    "GCM explicit IV",
			wantErr: errIVCipherMode,
			args:    []string{"aes", "encrypt", "plaintext", "--key", testAESKeyBase64, "--cipher-mode", "gcm", "--iv", testCBCIVBase64},
		},
		{
			name:    "GCM explicitly empty IV",
			wantErr: errIVCipherMode,
			args:    []string{"aes", "encrypt", "plaintext", "--key", testAESKeyBase64, "--cipher-mode", "gcm", "--iv="},
		},
		{
			name:    "CBC encrypt AAD",
			wantErr: errAADCipherMode,
			args:    []string{"aes", "encrypt", "plaintext", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--aad", "context"},
		},
		{
			name:    "CBC encrypt explicitly empty AAD",
			wantErr: errAADCipherMode,
			args:    []string{"aes", "encrypt", "plaintext", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--aad="},
		},
		{
			name:    "CBC decrypt AAD",
			wantErr: errAADCipherMode,
			args:    []string{"aes", "decrypt", testCBCCiphertextHex, "--input-encoding", "hex", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--aad", "context"},
		},
		{
			name:    "CBC decrypt explicitly empty AAD",
			wantErr: errAADCipherMode,
			args:    []string{"aes", "decrypt", testCBCCiphertextHex, "--input-encoding", "hex", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--aad="},
		},
		{
			name:    "unknown mode",
			wantErr: errUnknownAESCipherMode,
			args:    []string{"aes", "encrypt", "plaintext", "--key", testAESKeyBase64, "--cipher-mode", "unknown"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAESValidationPreservesOutput(t, test.args, test.wantErr)
		})
	}

	if decryptCmd.Flags().Lookup("iv") != nil {
		t.Fatal("aes decrypt unexpectedly exposes --iv")
	}
}

func TestAESAADUsesExactStringBytes(t *testing.T) {
	aad := string([]byte{0x00, 0xff, 'N', 'P', 'C', 0x00})
	plaintext := []byte("exact AAD bytes")
	wire, err := executeRoot(t, "aes", "encrypt", string(plaintext), "--key", testAESKeyBase64, "--aad", aad)
	if err != nil {
		t.Fatal(err)
	}

	key, err := base64.StdEncoding.DecodeString(testAESKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(wire)
	if len(encoded) < 12+gcm.Overhead() {
		t.Fatalf("GCM wire length = %d, want at least 28", len(encoded))
	}
	opened, err := gcm.Open(nil, encoded[:12], encoded[12:], []byte(aad))
	if err != nil {
		t.Fatalf("independent GCM Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("independent GCM plaintext = %q, want %q", opened, plaintext)
	}

	inputPath := writeTestFile(t, "gcm-wire", encoded)
	decrypted, err := executeRoot(t, "aes", "decrypt", "--key", testAESKeyBase64, "--aad", aad, "--input", inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != string(plaintext) {
		t.Fatalf("CLI GCM plaintext = %q, want %q", decrypted, plaintext)
	}
}

func TestAESDefaultAndExplicitGCMCrossDecrypt(t *testing.T) {
	const plaintext = "default and explicit GCM"
	const aad = "cross-mode context"
	for _, test := range []struct {
		name        string
		encryptMode []string
		decryptMode []string
	}{
		{name: "default to explicit", decryptMode: []string{"--cipher-mode", "gcm"}},
		{name: "explicit to default", encryptMode: []string{"--cipher-mode", "gcm"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			encryptArgs := []string{"aes", "encrypt", plaintext, "--key", testAESKeyBase64, "--aad", aad}
			encryptArgs = append(encryptArgs, test.encryptMode...)
			wire, err := executeRoot(t, encryptArgs...)
			if err != nil {
				t.Fatal(err)
			}
			inputPath := writeTestFile(t, "gcm-wire", []byte(wire))
			decryptArgs := []string{"aes", "decrypt", "--key", testAESKeyBase64, "--aad", aad, "--input", inputPath}
			decryptArgs = append(decryptArgs, test.decryptMode...)
			opened, err := executeRoot(t, decryptArgs...)
			if err != nil {
				t.Fatal(err)
			}
			if opened != plaintext {
				t.Fatalf("plaintext = %q, want %q", opened, plaintext)
			}
		})
	}
}

func TestAESGCMInputOutputEncodingRoundTrips(t *testing.T) {
	const plaintext = "GCM encoding round trip"
	for _, encoding := range byteEncodingNames() {
		t.Run(encoding, func(t *testing.T) {
			wire, err := executeRoot(
				t,
				"aes", "encrypt", plaintext,
				"--cipher-mode", "gcm",
				"--key", testAESKeyBase64,
				"--encoding", encoding,
			)
			if err != nil {
				t.Fatal(err)
			}
			inputPath := writeTestFile(t, "encoded-wire", []byte(wire))
			opened, err := executeRoot(
				t,
				"aes", "decrypt",
				"--cipher-mode", "gcm",
				"--key", testAESKeyBase64,
				"--input", inputPath,
				"--input-encoding", encoding,
			)
			if err != nil {
				t.Fatal(err)
			}
			if opened != plaintext {
				t.Fatalf("plaintext = %q, want %q", opened, plaintext)
			}
		})
	}
}

func TestAESRootOutputModeAndCBCCipherModeCompose(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "cbc-wire")
	_, err := executeRoot(
		t,
		"aes", "encrypt", testCBCPlaintext,
		"--cipher-mode", "cbc",
		"--key", testAESKeyBase64,
		"--iv", testCBCIVBase64,
		"--output", outputPath,
		"--mode", "0640",
	)
	if runtime.GOOS == "windows" {
		assertWindowsModeRejection(t, err, outputPath, "")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("output mode = %04o, want 0640", info.Mode().Perm())
	}
	opened, err := executeRoot(t, "aes", "decrypt", "--cipher-mode", "cbc", "--key", testAESKeyBase64, "--input", outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if opened != testCBCPlaintext {
		t.Fatalf("CBC plaintext = %q, want %q", opened, testCBCPlaintext)
	}
}

func TestAESCBCCLICompatibilityFixture(t *testing.T) {
	wire, err := executeRoot(
		t,
		"aes", "encrypt", testCBCPlaintext,
		"--cipher-mode", "cbc",
		"--key", testAESKeyBase64,
		"--iv", testCBCIVBase64,
		"--encoding", "hex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if wire != testCBCCiphertextHex {
		t.Fatalf("CBC compatibility ciphertext = %s, want %s", wire, testCBCCiphertextHex)
	}

	opened, err := executeRoot(
		t,
		"aes", "decrypt", testCBCCiphertextHex,
		"--cipher-mode", "cbc",
		"--key", testAESKeyBase64,
		"--input-encoding", "hex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if opened != testCBCPlaintext {
		t.Fatalf("CBC compatibility plaintext = %q, want %q", opened, testCBCPlaintext)
	}
}

func TestAESGCMRuntimeFailuresDoNotWritePlaintext(t *testing.T) {
	dir := t.TempDir()
	readFailurePath := filepath.Join(dir, "read-failure")
	if err := os.Mkdir(readFailurePath, 0o700); err != nil {
		t.Fatal(err)
	}
	sizePath := filepath.Join(dir, "too-large")
	file, err := os.Create(sizePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(sizePath, testGCMMaximumPlaintext+1); err != nil {
		t.Fatal(err)
	}
	malformedPath := writeTestFile(t, "malformed", make([]byte, 27))
	cbcWire, err := hex.DecodeString(testCBCCiphertextHex)
	if err != nil {
		t.Fatal(err)
	}
	cbcPath := writeTestFile(t, "cbc-as-gcm", cbcWire)

	for _, test := range []struct {
		wantErr error
		name    string
		args    []string
	}{
		{name: "read", args: []string{"aes", "encrypt", "--key", testAESKeyBase64, "--input", readFailurePath}},
		{name: "size", wantErr: crypter.ErrInputTooLarge, args: []string{"aes", "encrypt", "--key", testAESKeyBase64, "--input", sizePath}},
		{name: "malformed", wantErr: crypter.ErrMalformedCiphertext, args: []string{"aes", "decrypt", "--key", testAESKeyBase64, "--input", malformedPath}},
		{
			name:    "CBC selected as GCM authentication",
			wantErr: crypter.ErrAuthenticationFailed,
			args:    []string{"aes", "decrypt", "--key", testAESKeyBase64, "--input", cbcPath},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, _, err := executeRootStreams(t, test.args...)
			assertRuntimeFailure(t, err, test.wantErr)
			if stdout != "" {
				t.Fatalf("stdout = %q, want no crypter/plaintext output", stdout)
			}

			outputPath := filepath.Join(t.TempDir(), "existing-output")
			if err := os.WriteFile(outputPath, []byte(testPreservedOutput), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append(slices.Clone(test.args), "--output", outputPath)
			_, err = executeRoot(t, args...)
			assertRuntimeFailure(t, err, test.wantErr)
			output, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(output) != 0 {
				t.Fatalf("runtime failure output = %q, want truncated empty file", output)
			}
		})
	}
}

func assertAESValidationPreservesOutput(t *testing.T, args []string, target error) {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "existing-output")
	if err := os.WriteFile(outputPath, []byte(testPreservedOutput), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(slices.Clone(args), "--output", outputPath)
	if _, err := executeRoot(t, args...); !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != testPreservedOutput {
		t.Fatalf("validation failure output = %q, want preserved content", output)
	}
}

func assertRuntimeFailure(t *testing.T, err, target error) {
	t.Helper()
	if err == nil {
		t.Fatal("command succeeded, want runtime failure")
	}
	if target != nil && !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

func writeTestFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func modeName(mode string) string {
	if mode == "" {
		return "empty"
	}
	return mode
}
