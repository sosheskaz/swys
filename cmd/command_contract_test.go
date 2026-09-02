package cmd

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestBareNounsShowHelpWithoutSideEffects(t *testing.T) {
	for _, name := range []string{"aes", "cert", "key", "net"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "should-not-exist")
			output, err := executeRoot(t, name, "--output", path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output, "Usage:") {
				t.Fatalf("output = %q, want command help", output)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output file stat error = %v, want not-exist", err)
			}
		})
	}
}

func TestLegacyX509ForwardsToCertificateInspection(t *testing.T) {
	certificate := newTLSCertificateChain(t).Certificate[0]
	path := filepath.Join(t.TempDir(), "certificate.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, alias := range certCmd.Aliases {
		t.Run(alias, func(t *testing.T) {
			stdout, stderr, err := executeRootStreams(t, alias, "--input", path, "--format", "pem")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout, "-----BEGIN CERTIFICATE-----") || strings.Contains(stdout, "Usage:") {
				t.Fatalf("stdout = %q, want certificate output", stdout)
			}
			if !strings.Contains(stderr, "npc "+alias+" is deprecated") || !strings.Contains(stderr, "cert inspect") {
				t.Fatalf("stderr = %q, want %s migration warning", stderr, alias)
			}
		})
	}
}

func TestKeyGenerateRequiresAlgorithmAndPreservesLegacyCompatibility(t *testing.T) {
	if _, err := executeRoot(t, "key", "generate"); err == nil || !strings.Contains(err.Error(), "accepts 1 arg(s), received 0") {
		t.Fatalf("missing algorithm error = %v, want exact-args error", err)
	}
	if _, err := executeRoot(t, "key", "generate", "ed25519", "rsa2048"); err == nil || !strings.Contains(err.Error(), "received 2") {
		t.Fatalf("extra algorithm error = %v, want exact-args error", err)
	}

	canonical, err := executeRoot(t, "key", "generate", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	key, err := asym.ParseKey([]byte(canonical))
	if err != nil {
		t.Fatal(err)
	}
	info, err := key.Info()
	if err != nil {
		t.Fatal(err)
	}
	if !key.IsPrivate() || info.Algorithm != "ed25519" {
		t.Fatalf("default key info = %+v, want private Ed25519", info)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy-key")
	stdout, stderr, err := executeRootStreams(t, "aes", "genkey", "--output", legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Fatalf("aes genkey stdout = %q, want key redirected to file", stdout)
	}
	if !strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "key generate") {
		t.Fatalf("aes genkey stderr = %q, want migration warning", stderr)
	}
	legacy, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 16 {
		t.Fatalf("aes genkey length = %d, want 16", len(legacy))
	}
	if !genkeyCmd.Hidden || !strings.Contains(genkeyCmd.Long, "Deprecated:") {
		t.Fatal("aes genkey must be hidden and described as deprecated")
	}
}

func TestOldOutputFlagNamesAreRemoved(t *testing.T) {
	tests := [][]string{
		{"key", "generate", "ed25519", "--format", "base64"},
		{"cert", "inspect", "--output-format", "json"},
	}
	for _, args := range tests {
		if _, err := executeRoot(t, args...); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Fatalf("execute %v error = %v, want unknown flag", args, err)
		}
	}
}

func TestCertificateFormatRejectsLegacyEncodingWithMigrationHint(t *testing.T) {
	_, err := executeRoot(t, "cert", "inspect", "--format", "hex")
	if !errors.Is(err, errFormatSelectsStructuredOutput) {
		t.Fatalf("error = %v, want format-axis migration hint", err)
	}
}

func TestAESInputOutputEncodingRoundTrip(t *testing.T) {
	const plaintext = "encoding round trip"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	iv := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789"))
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte(plaintext), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, encoding := range byteEncodingNames() {
		t.Run(encoding, func(t *testing.T) {
			ciphertext, err := executeRoot(
				t,
				"aes", "encrypt",
				"--cipher-mode", "cbc",
				"--key", key,
				"--iv", iv,
				"--input", plainPath,
				"--encoding", encoding,
			)
			if err != nil {
				t.Fatal(err)
			}
			cipherPath := filepath.Join(t.TempDir(), "ciphertext")
			if err := os.WriteFile(cipherPath, []byte(ciphertext), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := executeRoot(
				t,
				"aes", "decrypt",
				"--cipher-mode", "cbc",
				"--key", key,
				"--input", cipherPath,
				"--input-encoding", encoding,
			)
			if err != nil {
				t.Fatal(err)
			}
			if output != plaintext {
				t.Fatalf("plaintext = %q, want %q", output, plaintext)
			}
		})
	}
}

func TestBase64URLEncodingIsUnpadded(t *testing.T) {
	output, err := executeRoot(t, "key", "generate", "aes-128", "--encoding", "base64url")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "=") {
		t.Fatalf("base64url output = %q, want no padding", output)
	}
}

func TestBase64URLInputAcceptsPadding(t *testing.T) {
	const plaintext = "padded base64url"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	iv := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789"))
	rawCiphertext, err := executeRoot(t, "aes", "encrypt", plaintext, "--cipher-mode", "cbc", "--key", key, "--iv", iv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ciphertext")
	padded := base64.URLEncoding.EncodeToString([]byte(rawCiphertext))
	if err := os.WriteFile(path, []byte(padded), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeRoot(
		t,
		"aes", "decrypt", "--cipher-mode", "cbc", "--key", key,
		"--input", path,
		"--input-encoding", "base64url",
	)
	if err != nil {
		t.Fatal(err)
	}
	if output != plaintext {
		t.Fatalf("plaintext = %q, want %q", output, plaintext)
	}
}

func TestHexInputAcceptsTrailingNewline(t *testing.T) {
	const plaintext = "trailing newline"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	iv := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789"))
	ciphertext, err := executeRoot(t, "aes", "encrypt", plaintext, "--cipher-mode", "cbc", "--key", key, "--iv", iv, "--encoding", "hex")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ciphertext")
	if err := os.WriteFile(path, []byte(ciphertext+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeRoot(
		t,
		"aes", "decrypt", "--cipher-mode", "cbc", "--key", key,
		"--input", path,
		"--input-encoding", "hex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if output != plaintext {
		t.Fatalf("plaintext = %q, want %q", output, plaintext)
	}
}

func TestUnknownInputEncodingDoesNotTruncateOutput(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input")
	outputPath := filepath.Join(dir, "output")
	if err := os.WriteFile(inputPath, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err := executeRoot(
		t,
		"aes", "decrypt", "--key", key,
		"--input", inputPath,
		"--input-encoding", "rot13",
		"--output", outputPath,
	)
	if !errors.Is(err, errUnknownInputEncoding) {
		t.Fatalf("error = %v, want unknown input encoding", err)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("output = %q, want preserved content", data)
	}
}

func TestNetworkCommandValidatesAddressBeforeIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "cert", "connect", "not-an-address", "--output", path)
	if !errors.Is(err, errInvalidHostPort) {
		t.Fatalf("error = %v, want invalid host:port", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("output = %q, want preserved content", data)
	}
}

func TestNetworkCommandRejectsNegativeTimeoutBeforeIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "cert", "connect", "localhost:443", "--timeout", "-1s", "--output", path)
	if !errors.Is(err, errInvalidNetworkFlags) {
		t.Fatalf("error = %v, want errInvalidNetworkFlags", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("output = %q, want preserved content", data)
	}
}

func TestNetworkCommandAppliesTimeout(t *testing.T) {
	var remaining time.Duration
	command := networkCommand(&cobra.Command{
		Use:    "network-test host:port",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			deadline, ok := cmd.Context().Deadline()
			if !ok {
				t.Fatal("network command context has no deadline")
			}
			remaining = time.Until(deadline)
			return nil
		},
	})
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	if _, err := executeRoot(t, "network-test", "example.com:443", "--timeout", "2s"); err != nil {
		t.Fatal(err)
	}
	if remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("remaining timeout = %v, want (0, 2s]", remaining)
	}
	if got := command.Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Fatalf("timeout default = %q, want 10s", got)
	}
}

func TestNetworkCommandZeroTimeoutDisablesDeadline(t *testing.T) {
	command := networkCommand(&cobra.Command{
		Use:    "network-zero-timeout-test host:port",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if deadline, ok := cmd.Context().Deadline(); ok {
				t.Fatalf("network command deadline = %v, want none", deadline)
			}
			return nil
		},
	})
	rootCmd.AddCommand(command)
	t.Cleanup(func() { rootCmd.RemoveCommand(command) })

	if _, err := executeRoot(t, "network-zero-timeout-test", "example.com:443", "--timeout", "0"); err != nil {
		t.Fatal(err)
	}
}

func TestCertConnectHelpDocumentsZeroTimeout(t *testing.T) {
	output, err := executeRoot(t, "cert", "connect", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "TCP setup and TLS handshake timeout (0 disables)") {
		t.Fatalf("help = %q, want zero-timeout behavior", output)
	}
}
