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
)

func TestOutputEncodingDoesNotTruncate(t *testing.T) {
	tests := []struct {
		name   string
		format string
		decode func(string) ([]byte, error)
	}{
		{name: "base64", format: "base64", decode: base64.StdEncoding.DecodeString},
		{name: "b64", format: "b64", decode: base64.StdEncoding.DecodeString},
		{name: "base64url", format: "base64url", decode: base64.RawURLEncoding.DecodeString},
		{name: "base32", format: "base32", decode: base32.StdEncoding.DecodeString},
		{name: "hex", format: "hex", decode: hex.DecodeString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeRoot(t, "key", "generate", "--bits", "128", "--encoding", tt.format)
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
	_, err := executeRoot(t, "key", "generate", "--bits", "64")
	if err == nil || !strings.Contains(err.Error(), "128, 192, or 256") {
		t.Fatalf("error = %v, want invalid AES key size", err)
	}
}

func TestUnknownOutputEncodingFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "key", "generate", "--encoding", "rot13", "--output", path)
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
	assertNoStagedOutputs(t, path)
}

func TestDecryptFailureDoesNotCommitPartialPlaintext(t *testing.T) {
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
		"aes", "encrypt", "--key", key, "--iv", iv, "--input", plaintextPath,
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
		"aes", "decrypt", "--key", key, "--input", ciphertextPath, "--output", outputPath,
	)
	if err == nil || !strings.Contains(err.Error(), "invalid PKCS#7 padding") {
		t.Fatalf("error = %v, want invalid padding", err)
	}
	output, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(output) != "preserve" {
		t.Fatalf("failed decrypt replaced output with %d bytes", len(output))
	}
	assertNoStagedOutputs(t, outputPath)
}

func TestSameInputAndOutputFileIsRejectedWithoutTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	const original = "keep me"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "key", "generate", "--input", path, "--output", path)
	if err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("error = %v, want same-file rejection", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("file content = %q, want %q", data, original)
	}
}

func TestOutputFileUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := executeRoot(t, "key", "generate", "--output", path); err != nil {
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
	assertNoStagedOutputs(t, path)
}

func TestOutputFileOverwriteKeepsExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "key", "generate", "--output", path); err != nil {
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
	assertNoStagedOutputs(t, path)
}

func TestOutputFileOverwritePreservesZeroPermissions(t *testing.T) {
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
	if _, err := executeRoot(t, "key", "generate", "--output", path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o000 {
		t.Fatalf("output permissions = %04o, want preserved 0000", got)
	}
	assertNoStagedOutputs(t, path)
}

func TestNonRegularOutputStreamsDirectly(t *testing.T) {
	output, err := executeRoot(t, "key", "generate", "--output", os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if output != "" {
		t.Fatalf("stdout = %q, want output redirected to %s", output, os.DevNull)
	}
}

func TestSymlinkOutputReplacesLinkWithoutModifyingTarget(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target")
	linkPath := filepath.Join(dir, "link")
	if err := os.WriteFile(targetPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	if _, err := executeRoot(t, "key", "generate", "--output", linkPath); err != nil {
		t.Fatal(err)
	}
	target, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(target) != "preserve" {
		t.Fatalf("symlink target = %q, want preserved content", target)
	}
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("output path remains a symlink; want atomic replacement")
	}
	replacement, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(replacement) != 32 {
		t.Fatalf("replacement length = %d, want 32", len(replacement))
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

	_, directErr := executeRoot(t, "key", "generate", "--output", targetDir)
	if directErr == nil || !strings.Contains(directErr.Error(), "is a directory") {
		t.Fatalf("direct directory error = %v, want directory rejection", directErr)
	}

	_, symlinkErr := executeRoot(t, "key", "generate", "--output", linkPath)
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

	// The root PersistentPreRunE owns --output and --encoding; the root
	// PersistentPostRunE commits the staged file.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("root hooks did not apply --output: %v", err)
	}
	if string(data) != "41" {
		t.Fatalf("output = %q, want %q from the root hook's hex encoder", data, "41")
	}
	assertNoStagedOutputs(t, outputPath)
}

func TestCommandErrorStillFlushesOutputEncoder(t *testing.T) {
	runErr := errors.New("command failed")
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

func TestCommandErrorDoesNotCommitOutputFile(t *testing.T) {
	runErr := errors.New("command failed")
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
	if string(data) != "preserve" {
		t.Fatalf("failed command replaced output with %q", data)
	}
	assertNoStagedOutputs(t, path)
}

func assertNoStagedOutputs(t *testing.T, outputPath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staged outputs remain after failure: %v", matches)
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
