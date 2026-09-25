package aes_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

const (
	testAESStreamDefaultChunkSize = 1024 * 1024
)

func TestExampleAESStreamingFileRoundTrip(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	keyPath := filepath.Join(directory, "aes.key")
	plaintextPath := filepath.Join(directory, "message.txt")
	ciphertextPath := filepath.Join(directory, "message.npcenc")
	openedPath := filepath.Join(directory, "opened.txt")
	plaintext := []byte("authenticated streaming example\n")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600))
	require.NoError(t, os.WriteFile(plaintextPath, plaintext, 0o600))

	if _, err := executeRoot(
		t,
		"aes", "encrypt", "--keyfile", keyPath,
		"--input", plaintextPath, "--output", ciphertextPath,
	); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(ciphertextPath)
	require.NoError(t, err)
	if len(ciphertext) < testAESStreamHeaderSize {
		t.Fatalf("ciphertext length = %d, want at least %d", len(ciphertext), testAESStreamHeaderSize)
	}
	header := ciphertext[:testAESStreamHeaderSize]
	if got := string(header[:8]); got != "NPCENC\r\n" {
		t.Fatalf("stream magic = %q, want %q", got, "NPCENC\\r\\n")
	}
	if header[8] != 1 || header[9] != 2 {
		t.Fatalf("stream version/suite = %d/%d, want 1/2", header[8], header[9])
	}
	if got := binary.BigEndian.Uint16(header[10:12]); got != testAESStreamHeaderSize {
		t.Fatalf("stream header length = %d, want %d", got, testAESStreamHeaderSize)
	}
	if got := binary.BigEndian.Uint32(header[12:16]); got != testAESStreamDefaultChunkSize {
		t.Fatalf("stream chunk size = %d, want %d", got, testAESStreamDefaultChunkSize)
	}

	if _, err := executeRoot(
		t,
		"aes", "decrypt", "--keyfile", keyPath,
		"--input", ciphertextPath, "--output", openedPath,
	); err != nil {
		t.Fatal(err)
	}
	opened, err := os.ReadFile(openedPath)
	require.NoError(t, err)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q, want %q", opened, plaintext)
	}
}

//nolint:paralleltest // The greater-than-64-MiB round trip is intentionally serial to bound peak memory.
func TestExampleAESStreamingLargerThanSingleMessageFileRoundTrip(t *testing.T) {
	const plaintextSize = 64*1024*1024 + 1

	directory := t.TempDir()
	keyPath := filepath.Join(directory, "aes.key")
	plaintextPath := filepath.Join(directory, "payload.bin")
	ciphertextPath := filepath.Join(directory, "payload.npcenc")
	openedPath := filepath.Join(directory, "opened.bin")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x24}, 32), 0o600))
	plaintext, err := os.Create(plaintextPath)
	require.NoError(t, err)
	if err := plaintext.Truncate(plaintextSize); err != nil {
		t.Fatal(errors.Join(err, plaintext.Close()))
	}
	require.NoError(t, plaintext.Close())
	wantDigest := testcmd.FileSHA256(t, plaintextPath)

	if _, err := executeRoot(
		t,
		"aes", "encrypt", "--keyfile", keyPath,
		"--input", plaintextPath, "--output", ciphertextPath,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(
		t,
		"aes", "decrypt", "--keyfile", keyPath,
		"--input", ciphertextPath, "--output", openedPath,
	); err != nil {
		t.Fatal(err)
	}
	if gotDigest := testcmd.FileSHA256(t, openedPath); gotDigest != wantDigest {
		t.Fatalf("opened plaintext SHA-256 = %q, want %q", gotDigest, wantDigest)
	}
}
