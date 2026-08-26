package cmd

import (
	"bytes"
	"crypto/aes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

var errTestCommandFailed = errors.New("command failed")

func TestOutputEncodingDoesNotTruncate(t *testing.T) {
	tests := []struct {
		decode func(string) ([]byte, error)
		name   string
		format string
	}{
		{name: "base64", format: "base64", decode: base64.StdEncoding.DecodeString},
		{name: "b64", format: "b64", decode: base64.StdEncoding.DecodeString},
		{name: "base64url", format: "base64url", decode: base64.RawURLEncoding.DecodeString},
		{name: "base32", format: "base32", decode: base32.StdEncoding.DecodeString},
		{name: "hex", format: "hex", decode: hex.DecodeString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeRoot(t, "key", "generate", "aes128", "--encoding", tt.format)
			if err != nil {
				t.Fatalf("execute command: %v", err)
			}
			decoded, err := tt.decode(strings.TrimSpace(output))
			if err != nil {
				t.Fatalf("decode output %q: %v", output, err)
			}
			if len(decoded) != 16 {
				t.Fatalf("decoded key length = %d, want 16", len(decoded))
			}
		})
	}
}

func TestGenkeyRejectsInvalidSize(t *testing.T) {
	_, err := executeRoot(t, "aes", "genkey", "--bits", "64")
	if !errors.Is(err, errInvalidAESKeySize) {
		t.Fatalf("error = %v, want errInvalidAESKeySize", err)
	}
}

func TestEncryptPreservesInvalidIVErrorIdentity(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	iv := base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize-1))

	_, err := executeRoot(t, "aes", "encrypt", "plaintext", "--cipher-mode", "cbc", "--key", key, "--iv", iv)
	if !errors.Is(err, crypter.ErrInvalidIVLength) {
		t.Fatalf("error = %v, want crypter.ErrInvalidIVLength", err)
	}
}

func TestUnknownOutputEncodingFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "key", "generate", "ed25519", "--encoding", "rot13", "--output", path)
	if err == nil || !errors.Is(err, errUnknownOutputEncoding) {
		t.Fatalf("error = %v, want unknown output encoding", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("invalid format truncated output file: %q", data)
	}
}

func TestFlagGroupValidationDoesNotTruncateOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "precious.dat")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "aes", "encrypt", "hello", "--output", path)
	if err == nil || !strings.Contains(err.Error(), "at least one of the flags") {
		t.Fatalf("error = %v, want missing key flag-group error", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("failed command replaced output with %q", data)
	}
}

func TestCommandErrorBeforeWriteLeavesEmptyOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("old contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "aes", "genkey", "--bits", "64", "--output", path)
	if !errors.Is(err, errInvalidAESKeySize) {
		t.Fatalf("error = %v, want invalid key size", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(data) != 0 {
		t.Fatalf("output length = %d, want empty file", len(data))
	}
}

func TestDecryptFailureLeavesStreamedPlaintext(t *testing.T) {
	dir := t.TempDir()
	plaintextPath := filepath.Join(dir, "plaintext")
	ciphertextPath := filepath.Join(dir, "ciphertext")
	outputPath := filepath.Join(dir, "output")
	plaintext := bytes.Repeat([]byte("A"), 64*1024+1)
	if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	iv := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789"))
	ciphertext, err := executeRoot(
		t,
		"aes", "encrypt", "--cipher-mode", "cbc", "--key", key, "--iv", iv, "--input", plaintextPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := []byte(ciphertext)
	corrupted[len(corrupted)-aes.BlockSize-1] ^= 1
	if err := os.WriteFile(ciphertextPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = executeRoot(
		t,
		"aes", "decrypt", "--cipher-mode", "cbc", "--key", key, "--input", ciphertextPath, "--output", outputPath,
	)
	if err == nil || !strings.Contains(err.Error(), "invalid PKCS#7 padding") {
		t.Fatalf("error = %v, want invalid padding", err)
	}
	output, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(output) != 64*1024 {
		t.Fatalf("failed decrypt output length = %d, want %d streamed bytes", len(output), 64*1024)
	}
	if !bytes.Equal(output[:len(output)-aes.BlockSize], plaintext[:len(output)-aes.BlockSize]) {
		t.Fatal("failed decrypt did not preserve the valid streamed plaintext prefix")
	}
}

func TestSameInputAndOutputFileIsRejectedWithoutTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	const original = "keep me"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "key", "generate", "ed25519", "--input", path, "--output", path)
	if !errors.Is(err, errSameInputOutput) {
		t.Fatalf("error = %v, want errSameInputOutput", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("file content = %q, want %q", data, original)
	}
}

func TestMissingInputIsRejectedBeforeOutputOpen(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "missing")
	outputPath := filepath.Join(dir, "output")
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	_, err := executeRoot(
		t,
		"aes", "encrypt", "--key", key,
		"--input", inputPath,
		"--output", outputPath,
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want missing-input error", err)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("output = %q, want preserved contents", data)
	}
}

func TestOutputFileUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 32 {
		t.Fatalf("output length = %d, want 32-byte replacement", len(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output permissions = %04o, want 0600", got)
	}
}

func TestOutputFileOverwriteKeepsExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 32 {
		t.Fatalf("output length = %d, want 32-byte replacement", len(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("output permissions = %04o, want preserved 0644", got)
	}
}

func TestOutputFileOverwriteKeepsExistingInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	alias := filepath.Join(dir, "key-alias")
	if err := os.WriteFile(path, []byte("old contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Skipf("create hard link: %v", err)
	}

	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 32 {
		t.Fatalf("hard-linked output length = %d, want 32", len(data))
	}
}

func TestOutputFileOverwriteRequiresWritePermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions; skipping under root")
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "key", "generate", "ed25519", "--output", path); err == nil {
		t.Fatal("execute command succeeded, want output-open error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o000 {
		t.Fatalf("output permissions = %04o, want unchanged 0000", got)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old contents" {
		t.Fatalf("output = %q, want original contents", data)
	}
}

func TestOutputModeSetsPermissionsOnNewFile(t *testing.T) {
	tests := []struct {
		modeText string
		want     os.FileMode
	}{
		{modeText: "0640", want: 0o640},
		{modeText: "640", want: 0o640},
		{modeText: "0000", want: 0o000},
	}
	for _, tt := range tests {
		t.Run(tt.modeText, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if _, err := executeRoot(t, "key", "generate", "ed25519", "--output", path, "--mode", tt.modeText); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != tt.want {
				t.Fatalf("output permissions = %04o, want %04o", got, tt.want)
			}
		})
	}
}

func TestOutputModeOverridesExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "key", "generate", "ed25519", "--output", path, "--mode", "0400"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("output permissions = %04o, want 0400 override", got)
	}
}

func TestInvalidOutputModeRejectedBeforeIO(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "empty", mode: ""},
		{name: "invalid-octal-digit", mode: "999"},
		{name: "invalid-octal-digit-leading-zero", mode: "0778"},
		{name: "non-numeric", mode: "abc"},
		{name: "exceeds-0777", mode: "1000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing")
			if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := executeRoot(t, "key", "generate", "ed25519", "--output", path, "--mode", tt.mode)
			if !errors.Is(err, errInvalidOutputMode) {
				t.Fatalf("error = %v, want invalid output mode", err)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != "preserve" {
				t.Fatalf("output = %q, want preserved content", data)
			}
		})
	}
}

func TestOutputModeWithoutOutputFlagIsRejected(t *testing.T) {
	_, err := executeRoot(t, "key", "generate", "ed25519", "--mode", "0640")
	if !errors.Is(err, errModeRequiresRegularOutput) {
		t.Fatalf("error = %v, want --mode-requires-regular-output", err)
	}
}

func TestOutputModeIsRejectedOnWindows(t *testing.T) {
	command := &cobra.Command{Use: "mode-test"}
	command.Flags().String("mode", "", "")
	if err := command.Flags().Set("mode", "0640"); err != nil {
		t.Fatal(err)
	}

	_, err := commandOutputOptionsForOS(command, "windows")
	if !errors.Is(err, errOutputModeUnsupported) {
		t.Fatalf("error = %v, want unsupported-output-mode", err)
	}
}

func TestModeFlagRegisteredOnRoot(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("mode")
	if flag == nil {
		t.Fatal("mode flag not registered")
	}
	if flag.DefValue != "" {
		t.Fatalf("mode default = %q, want empty (no override)", flag.DefValue)
	}
}

func TestNonRegularOutputStreamsDirectly(t *testing.T) {
	output, err := executeRoot(t, "key", "generate", "ed25519", "--output", os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if output != "" {
		t.Fatalf("stdout = %q, want output redirected to %s", output, os.DevNull)
	}
}

func TestSymlinkOutputFollowsTarget(t *testing.T) {
	tests := []struct {
		name     string
		modeArgs []string
		wantMode os.FileMode
	}{
		{name: "preserved-mode", wantMode: 0o600},
		{name: "explicit-mode", modeArgs: []string{"--mode", "0640"}, wantMode: 0o640},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			targetPath := filepath.Join(dir, "target")
			linkPath := filepath.Join(dir, "link")
			if err := os.WriteFile(targetPath, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(targetPath, linkPath); err != nil {
				t.Skipf("create symlink: %v", err)
			}

			args := append([]string{"key", "generate", "aes256", "--output", linkPath}, tt.modeArgs...)
			if _, err := executeRoot(t, args...); err != nil {
				t.Fatal(err)
			}
			target, err := os.ReadFile(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(target) != 32 {
				t.Fatalf("symlink target length = %d, want 32", len(target))
			}
			info, err := os.Lstat(linkPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("output path is no longer a symlink")
			}
			targetInfo, err := os.Stat(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := targetInfo.Mode().Perm(); got != tt.wantMode {
				t.Fatalf("output permissions = %04o, want %04o", got, tt.wantMode)
			}
		})
	}
}

func TestOutputModeFollowsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "missing-target")
	linkPath := filepath.Join(dir, "link")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", linkPath, "--mode", "0640"); err != nil {
		t.Fatal(err)
	}
	target, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(target) != 32 {
		t.Fatalf("symlink target length = %d, want 32", len(target))
	}
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("output path is no longer a symlink")
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := targetInfo.Mode().Perm(); got != 0o640 {
		t.Fatalf("output permissions = %04o, want 0640", got)
	}
}

func TestSymlinkOutputToDirectoryFailsLikeDirectDirectoryOutput(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "target-dir")
	linkPath := filepath.Join(dir, "link")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	_, directErr := executeRoot(t, "key", "generate", "ed25519", "--output", targetDir)
	if directErr == nil || !strings.Contains(directErr.Error(), "is a directory") {
		t.Fatalf("direct directory error = %v, want directory rejection", directErr)
	}

	_, symlinkErr := executeRoot(t, "key", "generate", "ed25519", "--output", linkPath)
	if symlinkErr == nil || !strings.Contains(symlinkErr.Error(), "is a directory") {
		t.Fatalf("symlinked directory error = %v, want directory rejection", symlinkErr)
	}
	if directErr.Error() != strings.ReplaceAll(symlinkErr.Error(), linkPath, targetDir) {
		t.Fatalf("error messages diverge: direct=%q symlink=%q", directErr, symlinkErr)
	}
}

func TestPersistentIOHooksApplyToNewCommands(t *testing.T) {
	command := binaryOutputCommand(&cobra.Command{
		Use:    "hook-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	output, err := executeRoot(t, "hook-test", "--encoding", "hex")
	if err != nil {
		t.Fatal(err)
	}
	if output != "41" {
		t.Fatalf("encoded output = %q, want 41", output)
	}
}

// Cobra runs only the nearest persistent hook unless traversal is enabled, so a
// descendant hook would otherwise shadow the root's and silently disable
// --input, --output, and encoding.
func TestDescendantPersistentHooksDoNotShadowRootIO(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "shadowed.bin")
	var childPreRan, childPostRan bool
	command := binaryOutputCommand(&cobra.Command{
		Use:    "shadow-hook-test",
		Hidden: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			childPreRan = true
			return nil
		},
		PersistentPostRunE: func(*cobra.Command, []string) error {
			childPostRan = true
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	if _, err := executeRoot(t, "shadow-hook-test", "--encoding", "hex", "--output", outputPath); err != nil {
		t.Fatal(err)
	}
	if !childPreRan || !childPostRan {
		t.Fatalf("descendant hooks did not run: pre=%v post=%v", childPreRan, childPostRan)
	}

	// The root PersistentPreRunE owns --output and --encoding.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("root hooks did not apply --output: %v", err)
	}
	if string(data) != "41" {
		t.Fatalf("output = %q, want %q from the root hook's hex encoder", data, "41")
	}
}

func TestOutputFileIsWrittenDuringCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("old contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	var observed []byte
	command := binaryOutputCommand(&cobra.Command{
		Use:    "live-output-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "live"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			var err error
			observed, err = os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read live output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	if _, err := executeRoot(t, "live-output-test", "--output", path); err != nil {
		t.Fatal(err)
	}
	if string(observed) != "live" {
		t.Fatalf("output observed during command = %q, want live data", observed)
	}
}

func TestOutputModeIsAppliedBeforeCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("old contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	var observed os.FileMode
	command := binaryOutputCommand(&cobra.Command{
		Use:    "output-mode-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("inspect output mode: %w", err)
			}
			observed = info.Mode().Perm()
			_, err = io.WriteString(cmd.OutOrStdout(), "output")
			if err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	if _, err := executeRoot(t, "output-mode-test", "--output", path, "--mode", "0640"); err != nil {
		t.Fatal(err)
	}
	if observed != 0o640 {
		t.Fatalf("output permissions during command = %04o, want 0640", observed)
	}
}

func TestCommandErrorStillFlushesOutputEncoder(t *testing.T) {
	runErr := errTestCommandFailed
	command := binaryOutputCommand(&cobra.Command{
		Use:    "hook-error-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return runErr
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	tests := []struct {
		encoding string
		want     string
	}{
		{encoding: "base64", want: "QQ=="},
		{encoding: "base64url", want: "QQ"},
		{encoding: "base32", want: "IE======"},
	}
	for _, tt := range tests {
		t.Run(tt.encoding, func(t *testing.T) {
			output, err := executeRoot(t, "hook-error-test", "--encoding", tt.encoding)
			if !errors.Is(err, runErr) {
				t.Fatalf("error = %v, want command failure", err)
			}
			if output != tt.want {
				t.Fatalf("encoded output = %q, want %q", output, tt.want)
			}
		})
	}
}

func TestCommandErrorLeavesWrittenOutputFile(t *testing.T) {
	runErr := errTestCommandFailed
	command := binaryOutputCommand(&cobra.Command{
		Use:    "output-error-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "replacement"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return runErr
		},
	}, false)
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "output-error-test", "--output", path, "--encoding", "base64")
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v, want command failure", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "cmVwbGFjZW1lbnQ=" {
		t.Fatalf("failed command output = %q, want flushed streamed data", data)
	}
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	resetCommandFlags(rootCmd)
	t.Cleanup(func() {
		resetCommandFlags(rootCmd)
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)
	command, runErr := rootCmd.ExecuteC()
	err := errors.Join(runErr, closeCommandIO(command))
	return stdout.String(), stderr.String(), err
}

func resetCommandFlags(command *cobra.Command) {
	command.SetIn(nil)
	command.SetOut(nil)
	command.SetErr(nil)
	reset := func(flag *pflag.Flag) {
		if slice, ok := flag.Value.(pflag.SliceValue); ok && flag.DefValue == "[]" {
			if err := slice.Replace(nil); err != nil {
				panic(err)
			}
			flag.Changed = false
			return
		}
		if err := flag.Value.Set(flag.DefValue); err != nil {
			panic(err)
		}
		flag.Changed = false
	}
	command.Flags().VisitAll(reset)
	command.PersistentFlags().VisitAll(reset)
	for _, child := range command.Commands() {
		resetCommandFlags(child)
	}
}
