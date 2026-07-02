package cmd

import (
	"bytes"
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
		{name: "hex", format: "hex", decode: hex.DecodeString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeRoot(t, "aes", "genkey", "--bits", "128", "--format", tt.format)
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
	if err == nil || !strings.Contains(err.Error(), "128, 192, or 256") {
		t.Fatalf("error = %v, want invalid AES key size", err)
	}
}

func TestUnknownOutputEncodingFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "aes", "genkey", "--format", "rot13", "--output", path)
	if err == nil || !strings.Contains(err.Error(), "unknown output encoding") {
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

func TestSameInputAndOutputFileIsRejectedWithoutTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	const original = "keep me"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "aes", "genkey", "--input", path, "--output", path)
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
	if _, err := executeRoot(t, "aes", "genkey", "--output", path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output permissions = %04o, want 0600", got)
	}
}

func TestPersistentIOHooksApplyToNewCommands(t *testing.T) {
	command := &cobra.Command{
		Use:    "hook-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return nil
		},
	}
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	output, err := executeRoot(t, "hook-test", "--format", "hex")
	if err != nil {
		t.Fatal(err)
	}
	if output != "41" {
		t.Fatalf("encoded output = %q, want 41", output)
	}
}

func TestCommandErrorStillFlushesOutputEncoder(t *testing.T) {
	runErr := errors.New("command failed")
	command := &cobra.Command{
		Use:    "hook-error-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return runErr
		},
	}
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	output, err := executeRoot(t, "hook-error-test", "--format", "base64")
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v, want command failure", err)
	}
	if output != "QQ==" {
		t.Fatalf("encoded output = %q, want QQ==", output)
	}
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetCommandFlags(rootCmd)
	t.Cleanup(func() {
		resetCommandFlags(rootCmd)
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	var output bytes.Buffer
	rootCmd.SetOut(&output)
	rootCmd.SetErr(&output)
	rootCmd.SetArgs(args)
	command, runErr := rootCmd.ExecuteC()
	err := errors.Join(runErr, closeCommandIO(command))
	return output.String(), err
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
