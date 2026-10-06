package aes_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cheapKDF keeps test derivations small; the default profile has its own example.
var cheapKDF = []string{"--kdf-memory", "8KiB", "--kdf-passes", "1", "--kdf-parallelism", "1"}

func TestExampleAESPasswordEnvironmentFileRoundTrip(t *testing.T) {
	t.Setenv("SWYS_TEST_AES_PASSWORD", "  correct horse 🔐  ")
	directory := t.TempDir()
	plain := filepath.Join(directory, "plain")
	cipher := filepath.Join(directory, "cipher")
	opened := filepath.Join(directory, "opened")
	want := []byte("password stream example\n")
	require.NoError(t, os.WriteFile(plain, want, 0o600))
	_, err := executeRoot(t, "aes", "encrypt", "--password-env", "SWYS_TEST_AES_PASSWORD", "--input", plain, "--output", cipher)
	require.NoError(t, err)
	wire, err := os.ReadFile(cipher)
	require.NoError(t, err)
	body := passwordWrapperBody(t, wire)
	require.Equal(t, []byte{6, 9, 4}, []byte{body[0], body[2], body[5]}, "SKESK v6, AES-256, Argon2")
	require.Equal(t, []byte{3, 4, 16}, body[22:25], "default Argon2id: 3 passes, 4 lanes, 64 MiB")
	_, err = executeRoot(t, "aes", "decrypt", "--password-env", "SWYS_TEST_AES_PASSWORD", "--input", cipher, "--output", opened)
	require.NoError(t, err)
	got, err := os.ReadFile(opened)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestExampleAESPasswordCommandWithPositionalEncoding(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell example")
	}
	stdout, _, err := executeRootStreams(t, append([]string{
		"aes", "encrypt", "secret message",
		"--password-command", "printf 'line password\\nignored\\n'", "--encoding", "base64",
	}, cheapKDF...)...)
	require.NoError(t, err)
	_, err = base64.StdEncoding.DecodeString(strings.TrimSpace(stdout))
	require.NoError(t, err)
	opened, _, err := executeRootStreams(t, "aes", "decrypt", strings.TrimSpace(stdout),
		"--password-command", "printf 'line password\\n'", "--input-encoding", "base64")
	require.NoError(t, err)
	require.Equal(t, "secret message", opened)
}

func TestAESPasswordPreflightKeepsOutput(t *testing.T) {
	t.Setenv("SWYS_TEST_AES_EMPTY", "")
	t.Setenv("SWYS_TEST_AES_PASSWORD", "synthetic password")
	directory := t.TempDir()
	output := filepath.Join(directory, "output")
	keyset := filepath.Join(directory, "keyset.json")
	message := filepath.Join(directory, "message.pgp")
	_, err := executeRoot(t, "aes", "keygen", "--key-format", "tink-json", "--output", keyset)
	require.NoError(t, err)
	env := []string{"--password-env", "SWYS_TEST_AES_PASSWORD"}
	_, err = executeRoot(t, append(append([]string{"aes", "encrypt", "payload", "--output", message}, env...), cheapKDF...)...)
	require.NoError(t, err)
	for _, test := range []struct {
		want string
		args []string
	}{
		{args: []string{"encrypt", "--password-env", "SWYS_TEST_AES_EMPTY"}, want: "password is empty"},
		{args: []string{"decrypt", "--password-env", "SWYS_TEST_AES_EMPTY", "--input", message}, want: "password is empty"},
		{args: []string{"encrypt", "--password=false"}, want: "--password=false"},
		{args: append([]string{"encrypt", "--wire-format", "tink"}, env...), want: "password"},
		{args: append([]string{"encrypt", "--key", keyset, "--key-format", "tink-json"}, env...), want: "none of the others can be"},
		{args: append([]string{"encrypt", "--key-id", "1"}, env...), want: "password"},
		{args: append([]string{"decrypt", "--allow-expensive-kdf"}, env...), want: "unknown flag"},
		{args: append([]string{"decrypt", "--kdf-passes", "1"}, env...), want: "unknown flag"},
		{args: []string{"encrypt", "--key-base64", "AAAAAAAAAAAAAAAAAAAAAA==", "--kdf-passes", "1"}, want: "requires a password"},
		{args: append([]string{"encrypt", "--kdf-memory", "96KiB"}, env...), want: "power of two"},
		{args: append([]string{"encrypt", "--kdf-memory", "64MB"}, env...), want: "power of two"},
		{args: append([]string{"encrypt", "--kdf-memory", "8KiB", "--kdf-parallelism", "2"}, env...), want: "at least 8 KiB per lane"},
		{args: append([]string{"encrypt", "--kdf-memory", "512MiB"}, env...), want: "Argon2 memory 524288 KiB exceeds limit 262144 KiB"},
		{args: append([]string{"encrypt", "--kdf-passes", "11"}, env...), want: "Argon2 passes 11 exceeds limit 10"},
		{args: append([]string{"encrypt", "--kdf-parallelism", "17"}, env...), want: "Argon2 lanes 17 exceeds limit 16"},
	} {
		require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
		args := append(append([]string{"aes"}, test.args...), "--output", output)
		_, err := executeRoot(t, args...)
		require.Error(t, err, "args: %v", args)
		require.ErrorContains(t, err, test.want, "args: %v", args)
		got, readErr := os.ReadFile(output)
		require.NoError(t, readErr)
		require.Equal(t, []byte("sentinel"), got, "args: %v", args)
	}
}

func TestAESPasswordDecryptRejectsCostlyWrappersBeforePassword(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell supplier records invocation")
	}
	directory := t.TempDir()
	wire, _, err := executeRootStreams(t, append([]string{
		"aes", "encrypt", "payload",
		"--password-command", "printf 'synthetic\\n'",
	}, cheapKDF...)...)
	require.NoError(t, err)
	wrapper := passwordWrapper(t, []byte(wire))
	patched := func(passes, lanes, memoryExponent byte) []byte {
		changed := bytes.Clone(wrapper)
		changed[24], changed[25], changed[26] = passes, lanes, memoryExponent
		return changed
	}
	message := func(wrappers ...[]byte) []byte {
		return append(slices.Concat(wrappers...), wire[len(wrapper):]...)
	}
	for _, test := range []struct {
		name string
		want string
		wire []byte
	}{
		{name: "passes", wire: message(patched(11, 1, 3)), want: "Argon2 passes 11 exceeds limit 10"},
		{name: "lanes", wire: message(patched(1, 17, 8)), want: "Argon2 lanes 17 exceeds limit 16"},
		{name: "memory", wire: message(patched(1, 1, 19)), want: "Argon2 memory 524288 KiB exceeds limit 262144 KiB"},
		{name: "cumulative", wire: message(patched(10, 1, 18), patched(1, 1, 3)), want: "cumulative Argon2 cost"},
		{name: "count", wire: message(slices.Repeat([][]byte{wrapper}, 17)...), want: "more than 16 password wrappers"},
		{name: "key message", wire: []byte(wire[len(wrapper):]), want: "no password wrapper"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := filepath.Join(directory, test.name+".pgp")
			output := filepath.Join(directory, test.name+".out")
			marker := filepath.Join(directory, test.name+".asked")
			require.NoError(t, os.WriteFile(input, test.wire, 0o600))
			require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
			_, err := executeRoot(t, "aes", "decrypt", "--input", input, "--output", output,
				"--password-command", "touch '"+marker+"'; printf 'synthetic\\n'")
			require.ErrorContains(t, err, test.want)
			require.NoFileExists(t, marker, "password was requested before KDF preflight")
			got, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, []byte("sentinel"), got)
		})
	}
}

func TestAESPasswordWrongCredentialKeepsOutput(t *testing.T) {
	t.Setenv("SWYS_TEST_AES_PASSWORD", "synthetic password")
	t.Setenv("SWYS_TEST_AES_WRONG", "synthetic wrong")
	directory := t.TempDir()
	input := filepath.Join(directory, "message.pgp")
	output := filepath.Join(directory, "opened")
	_, err := executeRoot(t, append([]string{
		"aes", "encrypt", "payload", "--password-env", "SWYS_TEST_AES_PASSWORD",
		"--output", input,
	}, cheapKDF...)...)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
	_, err = executeRoot(t, "aes", "decrypt", "--password-env", "SWYS_TEST_AES_WRONG", "--input", input, "--output", output)
	require.ErrorContains(t, err, "password does not match")
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("sentinel"), got)
	_, err = executeRoot(t, "aes", "decrypt", "--key-base64", base64.StdEncoding.EncodeToString(make([]byte, 32)), "--input", input)
	require.ErrorContains(t, err, "unexpected tag 3")
}

// passwordWrapper returns the leading one-octet-length SKESK packet.
func passwordWrapper(t *testing.T, wire []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(wire), 2)
	require.Equal(t, byte(0xc3), wire[0], "first packet must be a new-format SKESK")
	require.Less(t, wire[1], byte(192))
	return wire[:2+int(wire[1])]
}

func passwordWrapperBody(t *testing.T, wire []byte) []byte {
	t.Helper()
	body := passwordWrapper(t, wire)[2:]
	require.GreaterOrEqual(t, len(body), 25)
	return body
}
