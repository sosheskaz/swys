package cmd

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	byteencoding "github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	netcmd "github.com/sosheskaz-systems/npc/cmd/internal/commands/net"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestBareNounsShowHelpWithoutSideEffects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "aes", "cert", "net", "completion"} {
		testName := name
		if testName == "" {
			testName = "root"
		}
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "should-not-exist")
			args := []string{"--input", filepath.Join(dir, "missing-input"), "--output", path}
			if name != "" {
				args = append([]string{name}, args...)
			}
			root := NewCommand()
			root.SetIn(guidePanicReader{})
			output, err := executeRootCommand(t, root, args...)
			require.NoError(t, err)
			assert.Contains(t, output, "Usage:", "command help")
			_, err = os.Stat(path)
			assert.ErrorIs(t, err, os.ErrNotExist, "output file should not exist")
		})
	}
}

func TestBranchesRejectUnknownChildrenBeforeIO(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		branch        string
		wantErr       string
		ancestorFlags bool
	}{
		{name: "root", wantErr: `unknown command "typo" for "npc"`},
		{name: "aes", branch: "aes", wantErr: `unknown command "typo" for "npc aes"`},
		{name: "cert", branch: "cert", wantErr: `unknown command "typo" for "npc cert"`},
		{name: "certificate alias", branch: "x509", wantErr: `unknown command "typo" for "npc cert"`, ancestorFlags: true},
		{name: "net", branch: "net", wantErr: `unknown command "typo" for "npc net"`},
		{name: "network alias", branch: "nc", wantErr: `unknown command "typo" for "npc net"`},
		{name: "completion", branch: "completion", wantErr: `unknown command "typo" for "npc completion"`, ancestorFlags: true},
		{name: "hash keeps algorithm error", branch: "hash", wantErr: `unknown hash algorithm "typo"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			outputPath := filepath.Join(dir, "output")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			flags := []string{"--input", filepath.Join(dir, "missing-input"), "--output", outputPath}
			args := []string{"typo"}
			if test.branch != "" {
				args = append([]string{test.branch}, args...)
			}
			if test.ancestorFlags {
				args = append(flags, args...)
			} else {
				args = append(args, flags...)
			}
			root := NewCommand()
			root.SetIn(guidePanicReader{})
			stdout, stderr, err := executeRootCommandStreams(t, root, args...)
			require.ErrorContains(t, err, test.wantErr)
			assert.Empty(t, stdout, "invalid child must not fall back to help")
			assert.Empty(t, stderr, "root returns diagnostics to its caller")
			contents, readErr := os.ReadFile(outputPath)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(contents), "invalid child changed output")
		})
	}
}

func TestCertificateAliasesShowHelpWithoutSideEffects(t *testing.T) {
	t.Parallel()
	cert, _, findErr := NewCommand().Find([]string{"cert"})
	require.NoError(t, findErr)
	for _, alias := range cert.Aliases {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing-output")
			require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))

			rootCmd := newRootCmd()
			rootCmd.SetIn(panicCertificateReader{})
			stdout, stderr, err := executeRootCommandStreams(t, rootCmd, alias, "--output", path)
			require.NoError(t, err)
			assert.Contains(t, stdout, "Usage:", "command help")
			assert.Empty(t, stderr, "want no warning")
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(data), "preserved output contents")
		})
	}
}

func TestCertificateAliasSubcommandsMatchCanonicalCommand(t *testing.T) {
	t.Parallel()
	certificate := testcmd.NewTLSCertificateChain(t).Certificate[0]
	path := filepath.Join(t.TempDir(), "certificate.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: certificate})
	require.NoError(t, os.WriteFile(path, data, 0o600))

	wantStdout, wantStderr, err := executeRootStreams(t, "cert", "inspect", "--input", path, "--format", "pem")
	require.NoError(t, err)
	cert, _, findErr := NewCommand().Find([]string{"cert"})
	require.NoError(t, findErr)
	for _, alias := range cert.Aliases {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeRootStreams(t, alias, "inspect", "--input", path, "--format", "pem")
			require.NoError(t, err)
			assert.Equal(t, wantStdout, stdout, "alias stdout")
			assert.Equal(t, wantStderr, stderr, "alias stderr")

			for _, subcommand := range []string{"connect", "create", "csr", "inspect"} {
				output, err := executeRoot(t, alias, subcommand, "--help")
				require.NoError(t, err, "%s help", subcommand)
				assert.Contains(t, output, "Usage:", "%s help", subcommand)
				assert.NotContains(t, output, "deprecated", "%s help", subcommand)
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
	_, err := executeRoot(t, "cert", "keygen", "--algorithm", "missing")
	require.Error(t, err, "invalid algorithm accepted")
	_, err = executeRoot(t, "cert", "keygen", "rsa2048")
	require.ErrorContains(t, err, "unknown command")

	canonical, err := executeRoot(t, "cert", "keygen")
	require.NoError(t, err)
	key, err := asym.ParseKey([]byte(canonical))
	require.NoError(t, err)
	info, err := key.Info()
	require.NoError(t, err)
	assert.True(t, key.IsPrivate(), "default key must be private")
	assert.Equal(t, "ed25519", info.Algorithm, "default key algorithm")
}

func TestOldOutputFlagNamesAreRemoved(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"cert", "keygen", "--format", "base64"},
		{"cert", "inspect", "--output-format", "json"},
	}
	for _, args := range tests {
		_, err := executeRoot(t, args...)
		require.ErrorContains(t, err, "unknown flag", "execute %v", args)
	}
}

func TestAESInputOutputEncodingRoundTrip(t *testing.T) {
	t.Parallel()
	const plaintext = "encoding round trip"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	plainPath := filepath.Join(t.TempDir(), "plain")
	require.NoError(t, os.WriteFile(plainPath, []byte(plaintext), 0o600))

	for _, encoding := range byteencoding.Names() {
		t.Run(encoding, func(t *testing.T) {
			t.Parallel()
			ciphertext, err := executeRoot(
				t,
				"aes", "encrypt",
				"--key", key,
				"--input", plainPath,
				"--encoding", encoding,
			)
			require.NoError(t, err)
			cipherPath := filepath.Join(t.TempDir(), "ciphertext")
			require.NoError(t, os.WriteFile(cipherPath, []byte(ciphertext), 0o600))
			output, err := executeRoot(
				t,
				"aes", "decrypt",
				"--key", key,
				"--input", cipherPath,
				"--input-encoding", encoding,
			)
			require.NoError(t, err)
			assert.Equal(t, plaintext, output)
		})
	}
}

func TestBase64URLEncodingIsUnpadded(t *testing.T) {
	t.Parallel()
	output, err := executeRoot(t, "aes", "keygen", "--bits", "128", "--encoding", "base64url")
	require.NoError(t, err)
	assert.NotContains(t, output, "=", "base64url output must be unpadded")
}

func TestBase64URLInputAcceptsPadding(t *testing.T) {
	t.Parallel()
	const plaintext = "padded base64url"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	rawCiphertext, err := executeRoot(t, "aes", "encrypt", plaintext, "--key", key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ciphertext")
	padded := base64.URLEncoding.EncodeToString([]byte(rawCiphertext))
	require.NoError(t, os.WriteFile(path, []byte(padded), 0o600))
	output, err := executeRoot(
		t,
		"aes", "decrypt", "--key", key,
		"--input", path,
		"--input-encoding", "base64url",
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, output)
}

func TestHexInputAcceptsTrailingNewline(t *testing.T) {
	t.Parallel()
	const plaintext = "trailing newline"
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ciphertext, err := executeRoot(t, "aes", "encrypt", plaintext, "--key", key, "--encoding", "hex")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ciphertext")
	require.NoError(t, os.WriteFile(path, []byte(ciphertext+"\n"), 0o600))
	output, err := executeRoot(
		t,
		"aes", "decrypt", "--key", key,
		"--input", path,
		"--input-encoding", "hex",
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, output)
}

func TestUnknownInputEncodingDoesNotTruncateOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input")
	outputPath := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(inputPath, []byte("ciphertext"), 0o600))
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err := executeRoot(
		t,
		"aes", "decrypt", "--key", key,
		"--input", inputPath,
		"--input-encoding", "rot13",
		"--output", outputPath,
	)
	require.ErrorIs(t, err, byteencoding.ErrUnknownInputEncoding)
	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "preserved output")
}

func TestNetworkCommandValidatesAddressBeforeIO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, err := executeRoot(t, "cert", "connect", "not-an-address", "--output", path)
	require.ErrorIs(t, err, commandio.ErrInvalidHostPort)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "preserved output")
}

func TestNetworkCommandRejectsNegativeTimeoutBeforeIO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, err := executeRoot(t, "cert", "connect", "localhost:443", "--timeout", "-1s", "--output", path)
	require.ErrorIs(t, err, netcmd.ErrInvalidFlags)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "preserved output")
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
	require.NoError(t, err)
	assert.Contains(t, output, "TCP setup and TLS handshake timeout (0 disables)")
}

func TestOnlyKeyGenerationCommandsHaveSensitiveOutput(t *testing.T) {
	t.Parallel()
	root := NewCommand()
	for _, path := range [][]string{{"cert", "keygen"}, {"aes", "keygen"}} {
		command, _, err := root.Find(path)
		require.NoError(t, err)
		assert.True(t, commandio.HasShape(command, "sensitive-output"), "%s is not marked as sensitive output", command.CommandPath())
	}
	for _, path := range [][]string{{"cert", "key-public"}, {"cert", "key-inspect"}, {"cert", "key-convert"}, {"cert", "create"}, {"cert", "csr"}} {
		command, _, err := root.Find(path)
		require.NoError(t, err)
		assert.False(t, commandio.HasShape(command, "sensitive-output"), "%s is unexpectedly marked as sensitive output", command.CommandPath())
	}
}
