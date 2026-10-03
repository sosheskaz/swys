package aes_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExampleAESOpenPGPFileRoundTrip(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "aes.key")
	plaintextPath := filepath.Join(directory, "message.bin")
	ciphertextPath := filepath.Join(directory, "message.pgp")
	openedPath := filepath.Join(directory, "opened.bin")
	plaintext := []byte{0, 'f', 'i', 'l', 'e', '\n', 0xff}
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600))
	require.NoError(t, os.WriteFile(plaintextPath, plaintext, 0o600))

	_, err := executeRoot(t, "aes", "encrypt", "--key", keyPath,
		"--input", plaintextPath, "--output", ciphertextPath)
	require.NoError(t, err)
	wire, err := os.ReadFile(ciphertextPath)
	require.NoError(t, err)
	require.NotEmpty(t, wire)
	require.Equal(t, byte(0xd2), wire[0], "outer packet must be SEIPD")

	_, err = executeRoot(t, "aes", "decrypt", "--key", keyPath,
		"--input", ciphertextPath, "--output", openedPath)
	require.NoError(t, err)
	opened, err := os.ReadFile(openedPath)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}
