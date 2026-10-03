package cmd

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	byteencoding "github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	"github.com/sosheskaz-systems/npc/internal/securefile"
)

var errTestCommandFailed = errors.New("command failed")

func TestOutputEncodingDoesNotTruncate(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			output, err := executeRoot(t, "aes", "keygen", "--bits", "128", "--encoding", tt.format)
			require.NoError(t, err, "execute command")
			decoded, err := tt.decode(strings.TrimSpace(output))
			require.NoError(t, err, "decode output %q", output)
			assert.Len(t, decoded, 16, "decoded key")
		})
	}
}

func TestUnknownOutputEncodingFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, err := executeRoot(t, "cert", "keygen", "--encoding", "rot13", "--output", path)
	require.ErrorIs(t, err, byteencoding.ErrUnknownOutputEncoding)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "output after invalid format")
}

func TestFlagGroupValidationDoesNotTruncateOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "precious.dat")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))

	_, err := executeRoot(t, "aes", "encrypt", "hello", "--output", path)
	require.ErrorContains(t, err, "at least one of the flags", "missing key flag group")
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "output after failed command")
}

func TestSameInputAndOutputFileIsRejectedWithoutTruncation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "data")
	const original = "keep me"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))

	_, err := executeRoot(t, "cert", "keygen", "--input", path, "--output", path)
	require.ErrorIs(t, err, commandio.ErrSameInputOutput)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, original, string(data), "file content")
}

func TestMainStreamDashAndLiteralPaths(t *testing.T) { //nolint:paralleltest // literal paths require t.Chdir
	const digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
	for _, test := range []struct { //nolint:paralleltest // each subtest changes the working directory
		name, stdin, file, wantStdout, wantFile string
		args                                    []string
	}{
		{
			name: "literal input to stdout", stdin: "wrong source", file: "hello",
			args: []string{"--input", "./-", "--output", "-"}, wantStdout: digest, wantFile: "hello",
		},
		{
			name: "stdin to literal output", stdin: "hello", file: "preserve",
			args: []string{"--input", "-", "--output", "./-"}, wantFile: digest,
		},
		{
			name: "encoded shorthand streams", stdin: "aGVsbG8=", file: "preserve",
			args:       []string{"-i", "-", "-o", "-", "--input-encoding", "base64", "-e", "base64"},
			wantStdout: "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=\n", wantFile: "preserve",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, os.WriteFile("-", []byte(test.file), 0o600))
			root := NewCommand()
			root.SetIn(strings.NewReader(test.stdin))
			args := append([]string{"hash", "sha256"}, test.args...)
			stdout, stderr, err := executeRootCommandStreams(t, root, args...)
			require.NoError(t, err)
			assert.Equal(t, test.wantStdout, stdout)
			assert.Empty(t, stderr)
			contents, err := os.ReadFile("-")
			require.NoError(t, err)
			assert.Equal(t, test.wantFile, string(contents))
		})
	}
}

func TestMissingInputIsRejectedBeforeOutputOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "missing")
	outputPath := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	_, err := executeRoot(
		t,
		"aes", "encrypt", "--key", key,
		"--input", inputPath,
		"--output", outputPath,
	)
	require.ErrorIs(t, err, os.ErrNotExist)
	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(data), "output after missing input")
}

func TestOutputFileUsesPrivatePermissions(t *testing.T) {
	t.Parallel()
	commands := [][]string{{"aes", "keygen"}}
	for _, command := range commands {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "key")
			args := append(append([]string{}, command...), "--output", path)
			_, err := executeRoot(t, args...)
			require.NoError(t, err)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Len(t, data, 32, "output key")
			assertPrivateOutput(t, path)
		})
	}
}

func TestSensitiveOutputRejectsInsecureExistingFile(t *testing.T) {
	t.Parallel()
	commands := [][]string{{"aes", "keygen"}}
	for _, command := range commands {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "key")
			require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o644))
			before, statErr := os.Stat(path)
			require.NoError(t, statErr)
			args := append(append([]string{}, command...), "--output", path)
			_, err := executeRoot(t, args...)
			require.ErrorIs(t, err, securefile.ErrNotOwnerOnly)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "old contents", string(data), "existing output")
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, before.Mode().Perm(), info.Mode().Perm(), "output permissions")
		})
	}
}

func TestSensitiveOutputModeExplicitlyOverridesPolicy(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o644))
	_, runErr := executeRoot(t, "aes", "keygen", "--output", path, "--mode", "0640")
	if runtime.GOOS == "windows" {
		assertWindowsModeRejection(t, runErr, path, "old contents")
		return
	}
	require.NoError(t, runErr)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Len(t, data, 32, "output key")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "explicit output permissions")
}

func TestOrdinaryOutputKeepsExistingPermissions(t *testing.T) {
	t.Parallel()
	command := commandio.BinaryOutputCommand(&cobra.Command{
		Use:    "ordinary-output-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), "replacement")
			if err != nil {
				return fmt.Errorf("write ordinary output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	path := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o644))
	before, statErr := os.Stat(path)
	require.NoError(t, statErr)
	_, err := executeRootCommand(t, rootCmd, "ordinary-output-test", "--output", path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, before.Mode().Perm(), info.Mode().Perm(), "preserved output permissions")
}

func TestOutputFileOverwriteKeepsExistingInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	alias := filepath.Join(dir, "key-alias")
	writeOwnerOnlyFixture(t, path, "old contents")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("create hard link: %v", err)
	}

	_, err := executeRoot(t, "aes", "keygen", "--output", path)
	require.NoError(t, err)
	data, err := os.ReadFile(alias)
	require.NoError(t, err)
	assert.Len(t, data, 32, "hard-linked output")
}

func TestOutputFileOverwriteRequiresWritePermission(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions; skipping under root")
	}
	path := filepath.Join(t.TempDir(), "key")
	writeOwnerOnlyFixture(t, path, "old contents")
	require.NoError(t, os.Chmod(path, 0o000))
	before, statErr := os.Stat(path)
	require.NoError(t, statErr)
	_, err := executeRoot(t, "cert", "keygen", "--output", path)
	require.Error(t, err, "want output-open error")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, before.Mode().Perm(), info.Mode().Perm(), "unchanged output permissions")
	require.NoError(t, os.Chmod(path, 0o600))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "old contents", string(data), "existing output")
}

func TestOutputModeSetsPermissionsOnNewFile(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			path := filepath.Join(t.TempDir(), "key")
			_, runErr := executeRoot(t, "cert", "keygen", "--output", path, "--mode", tt.modeText)
			if runtime.GOOS == "windows" {
				assertWindowsModeRejection(t, runErr, path, "")
				return
			}
			require.NoError(t, runErr)
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, info.Mode().Perm(), "output permissions")
		})
	}
}

func TestOutputModeOverridesExistingPermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o644))
	_, runErr := executeRoot(t, "cert", "keygen", "--output", path, "--mode", "0400")
	if runtime.GOOS == "windows" {
		assertWindowsModeRejection(t, runErr, path, "old contents")
		return
	}
	require.NoError(t, runErr)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm(), "override output permissions")
}

func TestInvalidOutputModeRejectedBeforeIO(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing")
			require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
			_, err := executeRoot(t, "cert", "keygen", "--output", path, "--mode", tt.mode)
			wantErr := commandio.ErrInvalidOutputMode
			if runtime.GOOS == "windows" {
				wantErr = commandio.ErrOutputModeUnsupported
			}
			require.ErrorIs(t, err, wantErr)
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(data), "output after invalid mode")
		})
	}
}

func TestOutputModeWithoutOutputFlagIsRejected(t *testing.T) { //nolint:paralleltest // isolates a dash output if validation regresses
	for _, destination := range []string{"omitted", "dash"} { //nolint:paralleltest // each subtest changes the working directory
		t.Run(destination, func(t *testing.T) {
			t.Chdir(t.TempDir())
			input := &modeInputReader{}
			root := NewCommand()
			root.SetIn(input)
			args := []string{"hash", "sha256", "--mode", "0640"}
			if destination == "dash" {
				args = append(args, "--output", "-")
			}
			_, _, err := executeRootCommandStreams(t, root, args...)
			wantErr := commandio.ErrModeRequiresRegularOutput
			if runtime.GOOS == "windows" {
				wantErr = commandio.ErrOutputModeUnsupported
			}
			require.ErrorIs(t, err, wantErr)
			assert.Zero(t, input.reads.Load(), "output mode validation consumed stdin")
		})
	}
}

type modeInputReader struct{ reads atomic.Int32 }

func (reader *modeInputReader) Read([]byte) (int, error) {
	reader.reads.Add(1)
	return 0, errTestCommandFailed
}

func TestModeFlagRegisteredOnRoot(t *testing.T) {
	t.Parallel()
	flag := newRootCmd().PersistentFlags().Lookup("mode")
	require.NotNil(t, flag, "mode flag")
	assert.Empty(t, flag.DefValue, "mode default")
}

func TestNonRegularOutputStreamsDirectly(t *testing.T) {
	t.Parallel()
	output, err := executeRoot(t, "cert", "keygen", "--output", os.DevNull)
	require.NoError(t, err)
	assert.Empty(t, output, "stdout redirected to %s", os.DevNull)
}

func TestSymlinkOutputFollowsTarget(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			dir := t.TempDir()
			targetPath := filepath.Join(dir, "target")
			linkPath := filepath.Join(dir, "link")
			writeOwnerOnlyFixture(t, targetPath, "preserve")
			if err := os.Symlink(targetPath, linkPath); err != nil {
				t.Skipf("create symlink: %v", err)
			}

			args := append([]string{"aes", "keygen", "--output", linkPath}, tt.modeArgs...)
			_, runErr := executeRoot(t, args...)
			if runtime.GOOS == "windows" && len(tt.modeArgs) > 0 {
				assertWindowsModeRejection(t, runErr, targetPath, "preserve")
				return
			}
			require.NoError(t, runErr)
			target, err := os.ReadFile(targetPath)
			require.NoError(t, err)
			assert.Len(t, target, 32, "symlink target")
			info, err := os.Lstat(linkPath)
			require.NoError(t, err)
			assert.NotZero(t, info.Mode()&os.ModeSymlink, "output path is no longer a symlink")
			if runtime.GOOS == "windows" {
				assertPrivateOutput(t, targetPath)
			}
			targetInfo, err := os.Stat(targetPath)
			require.NoError(t, err)
			if runtime.GOOS != "windows" {
				assert.Equal(t, tt.wantMode, targetInfo.Mode().Perm(), "output permissions")
			}
		})
	}
}

func TestSensitiveOutputRejectsInsecureSymlinkTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target")
	linkPath := filepath.Join(dir, "link")
	require.NoError(t, os.WriteFile(targetPath, []byte("preserve"), 0o644))
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	_, err := executeRoot(t, "aes", "keygen", "--output", linkPath)
	require.ErrorIs(t, err, securefile.ErrNotOwnerOnly)
	data, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data), "symlink target contents")
	info, err := os.Lstat(linkPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "output path is no longer a symlink")
}

func TestOutputModeFollowsDanglingSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "missing-target")
	linkPath := filepath.Join(dir, "link")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	_, runErr := executeRoot(t, "aes", "keygen", "--output", linkPath, "--mode", "0640")
	if runtime.GOOS == "windows" {
		assertWindowsModeRejection(t, runErr, targetPath, "")
		return
	}
	require.NoError(t, runErr)
	target, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Len(t, target, 32, "symlink target")
	info, err := os.Lstat(linkPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "output path is no longer a symlink")
	targetInfo, err := os.Stat(targetPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), targetInfo.Mode().Perm(), "output permissions")
}

func TestSymlinkOutputToDirectoryFailsLikeDirectDirectoryOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "target-dir")
	linkPath := filepath.Join(dir, "link")
	require.NoError(t, os.Mkdir(targetDir, 0o700))
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	_, directErr := executeRoot(t, "cert", "keygen", "--output", targetDir)
	require.ErrorContains(t, directErr, "is a directory", "direct directory rejection")

	_, symlinkErr := executeRoot(t, "cert", "keygen", "--output", linkPath)
	require.ErrorContains(t, symlinkErr, "is a directory", "symlinked directory rejection")
	assert.Equal(t, directErr.Error(), strings.ReplaceAll(symlinkErr.Error(), strconv.Quote(linkPath), strconv.Quote(targetDir)), "directory errors")
}

func TestPersistentIOHooksApplyToNewCommands(t *testing.T) {
	t.Parallel()
	command := commandio.BinaryOutputCommand(&cobra.Command{
		Use:    "hook-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return nil
		},
	}, false)
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	output, err := executeRootCommand(t, rootCmd, "hook-test", "--encoding", "hex")
	require.NoError(t, err)
	assert.Equal(t, "41", output, "encoded output")
}

// Cobra runs only the nearest persistent hook unless traversal is enabled, so a
// descendant hook would otherwise shadow the root's and silently disable
// --input, --output, and encoding.
func TestDescendantPersistentHooksDoNotShadowRootIO(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "shadowed.bin")
	var childPreRan, childPostRan bool
	command := commandio.BinaryOutputCommand(&cobra.Command{
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
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	_, err := executeRootCommand(t, rootCmd, "shadow-hook-test", "--encoding", "hex", "--output", outputPath)
	require.NoError(t, err)
	assert.True(t, childPreRan, "descendant pre-hook")
	assert.True(t, childPostRan, "descendant post-hook")

	// The root PersistentPreRunE owns --output and --encoding.
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err, "root hooks apply --output")
	assert.Equal(t, "41", string(data), "root hex output encoder")
}

func TestOutputFileIsWrittenDuringCommand(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o600))

	var observed []byte
	command := commandio.BinaryOutputCommand(&cobra.Command{
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
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	_, err := executeRootCommand(t, rootCmd, "live-output-test", "--output", path)
	require.NoError(t, err)
	assert.Equal(t, "live", string(observed), "output observed during command")
}

func TestOutputModeIsAppliedBeforeCommand(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o600))

	var observed os.FileMode
	command := commandio.BinaryOutputCommand(&cobra.Command{
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
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	_, runErr := executeRootCommand(t, rootCmd, "output-mode-test", "--output", path, "--mode", "0640")
	if runtime.GOOS == "windows" {
		assertWindowsModeRejection(t, runErr, path, "old contents")
		assert.Zero(t, observed, "command observed mode after rejection")
		return
	}
	require.NoError(t, runErr)
	assert.Equal(t, os.FileMode(0o640), observed, "output permissions during command")
}

func TestCommandErrorStillFlushesOutputEncoder(t *testing.T) {
	t.Parallel()
	runErr := errTestCommandFailed

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
			t.Parallel()
			command := commandio.BinaryOutputCommand(&cobra.Command{
				Use:    "hook-error-test",
				Hidden: true,
				RunE: func(cmd *cobra.Command, _ []string) error {
					if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
						return fmt.Errorf("write test output: %w", err)
					}
					return runErr
				},
			}, false)
			rootCmd := newRootCmd()
			rootCmd.AddCommand(command)

			output, err := executeRootCommand(t, rootCmd, "hook-error-test", "--encoding", tt.encoding)
			require.ErrorIs(t, err, runErr)
			assert.Equal(t, tt.want, output, "encoded output")
		})
	}
}

func TestCommandErrorLeavesWrittenOutputFile(t *testing.T) {
	t.Parallel()
	runErr := errTestCommandFailed
	command := commandio.BinaryOutputCommand(&cobra.Command{
		Use:    "output-error-test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := io.WriteString(cmd.OutOrStdout(), "replacement"); err != nil {
				return fmt.Errorf("write test output: %w", err)
			}
			return runErr
		},
	}, false)
	rootCmd := newRootCmd()
	rootCmd.AddCommand(command)

	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, err := executeRootCommand(t, rootCmd, "output-error-test", "--output", path, "--encoding", "base64")
	require.ErrorIs(t, err, runErr)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "cmVwbGFjZW1lbnQ=", string(data), "flushed output after command error")
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return executeRootCommandStreams(t, newRootCmd(), args...)
}

func executeRootCommandStreams(t *testing.T, rootCmd *cobra.Command, args ...string) (string, string, error) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(args)
	command, runErr := rootCmd.ExecuteC()
	err := errors.Join(runErr, commandio.Close(command))
	return stdout.String(), stderr.String(), err
}

func executeRootCommand(t *testing.T, rootCmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootCommandStreams(t, rootCmd, args...)
	return stdout + stderr, err
}
