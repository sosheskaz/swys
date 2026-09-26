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

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	byteencoding "github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	netcmd "github.com/sosheskaz-systems/npc/cmd/internal/commands/net"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestBareNounsShowHelpWithoutSideEffects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"aes", "cert", "key", "net"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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

func TestCertificateAliasesShowHelpWithoutSideEffects(t *testing.T) {
	t.Parallel()
	cert, _, findErr := NewCommand().Find([]string{"cert"})
	if findErr != nil {
		t.Fatal(findErr)
	}
	for _, alias := range cert.Aliases {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing-output")
			if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}

			rootCmd := newRootCmd()
			rootCmd.SetIn(panicCertificateReader{})
			stdout, stderr, err := executeRootCommandStreams(t, rootCmd, alias, "--output", path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout, "Usage:") {
				t.Fatalf("stdout = %q, want command help", stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want no warning", stderr)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != "preserve" {
				t.Fatalf("output file = %q, want preserved contents", data)
			}
		})
	}
}

func TestCertificateAliasSubcommandsMatchCanonicalCommand(t *testing.T) {
	t.Parallel()
	certificate := testcmd.NewTLSCertificateChain(t).Certificate[0]
	path := filepath.Join(t.TempDir(), "certificate.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: certificate})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	wantStdout, wantStderr, err := executeRootStreams(t, "cert", "inspect", "--input", path, "--format", "pem")
	if err != nil {
		t.Fatal(err)
	}
	cert, _, findErr := NewCommand().Find([]string{"cert"})
	if findErr != nil {
		t.Fatal(findErr)
	}
	for _, alias := range cert.Aliases {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeRootStreams(t, alias, "inspect", "--input", path, "--format", "pem")
			if err != nil {
				t.Fatal(err)
			}
			if stdout != wantStdout || stderr != wantStderr {
				t.Fatalf("alias output = (%q, %q), want (%q, %q)", stdout, stderr, wantStdout, wantStderr)
			}

			for _, subcommand := range []string{"connect", "create", "csr", "inspect"} {
				output, err := executeRoot(t, alias, subcommand, "--help")
				if err != nil {
					t.Fatalf("%s help: %v", subcommand, err)
				}
				if !strings.Contains(output, "Usage:") || strings.Contains(output, "deprecated") {
					t.Fatalf("%s help = %q, want ordinary command help", subcommand, output)
				}
			}
		})
	}
}

type panicCertificateReader struct{}

func (panicCertificateReader) Read([]byte) (int, error) {
	panic("certificate alias help read stdin")
}

func TestKeyGenerateRequiresAlgorithm(t *testing.T) {
	t.Parallel()
	if _, err := executeRoot(t, "cert", "keygen", "--algorithm", "missing"); err == nil {
		t.Fatalf("invalid algorithm accepted")
	}
	if _, err := executeRoot(t, "cert", "keygen", "rsa2048"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("extra algorithm error = %v, want exact-args error", err)
	}

	canonical, err := executeRoot(t, "cert", "keygen")
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
}

func TestOldOutputFlagNamesAreRemoved(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"cert", "keygen", "--format", "base64"},
		{"cert", "inspect", "--output-format", "json"},
	}
	for _, args := range tests {
		if _, err := executeRoot(t, args...); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Fatalf("execute %v error = %v, want unknown flag", args, err)
		}
	}
}

func TestAESInputOutputEncodingRoundTrip(t *testing.T) {
	t.Parallel()
	const plaintext = "encoding round trip"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	iv := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789"))
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte(plaintext), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, encoding := range byteencoding.Names() {
		t.Run(encoding, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
	output, err := executeRoot(t, "aes", "keygen", "--bits", "128", "--encoding", "base64url")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "=") {
		t.Fatalf("base64url output = %q, want no padding", output)
	}
}

func TestBase64URLInputAcceptsPadding(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	if !errors.Is(err, byteencoding.ErrUnknownInputEncoding) {
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
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "cert", "connect", "not-an-address", "--output", path)
	if !errors.Is(err, commandio.ErrInvalidHostPort) {
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
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "cert", "connect", "localhost:443", "--timeout", "-1s", "--output", path)
	if !errors.Is(err, netcmd.ErrInvalidFlags) {
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
	t.Parallel()
	var remaining time.Duration
	command := commandio.NetworkCommand(&cobra.Command{
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
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	if _, err := executeRootCommand(t, rootCmd, "network-test", "example.com:443", "--timeout", "2s"); err != nil {
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
	t.Parallel()
	command := commandio.NetworkCommand(&cobra.Command{
		Use:    "network-zero-timeout-test host:port",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if deadline, ok := cmd.Context().Deadline(); ok {
				t.Fatalf("network command deadline = %v, want none", deadline)
			}
			return nil
		},
	})
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	if _, err := executeRootCommand(t, rootCmd, "network-zero-timeout-test", "example.com:443", "--timeout", "0"); err != nil {
		t.Fatal(err)
	}
}

func TestCertConnectHelpDocumentsZeroTimeout(t *testing.T) {
	t.Parallel()
	output, err := executeRoot(t, "cert", "connect", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "TCP setup and TLS handshake timeout (0 disables)") {
		t.Fatalf("help = %q, want zero-timeout behavior", output)
	}
}

func TestOnlyKeyGenerationCommandsHaveSensitiveOutput(t *testing.T) {
	t.Parallel()
	root := NewCommand()
	for _, path := range [][]string{{"cert", "keygen"}, {"aes", "keygen"}} {
		command, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		if !commandio.HasShape(command, "sensitive-output") {
			t.Fatalf("%s is not marked as sensitive output", command.CommandPath())
		}
	}
	for _, path := range [][]string{{"key", "public"}, {"key", "inspect"}, {"key", "convert"}, {"cert", "create"}, {"cert", "csr"}} {
		command, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		if commandio.HasShape(command, "sensitive-output") {
			t.Fatalf("%s is unexpectedly marked as sensitive output", command.CommandPath())
		}
	}
}
