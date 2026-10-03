package hash_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHashSHA256FromStdin(t *testing.T) {
	t.Parallel()

	output, err := executeHashCommand(t, bytes.NewBufferString("hello"), "hash", "sha256")
	require.NoError(t, err)
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
	assert.Equal(t, want, string(output), "npc hash sha256 output")
}

func TestExampleHashExplicitStreams(t *testing.T) { //nolint:paralleltest // isolates the literal dash fixture with t.Chdir
	t.Chdir(t.TempDir())
	const sentinel = "literal dash file"
	require.NoError(t, os.WriteFile("-", []byte(sentinel), 0o600))
	input := &hashBorrowedStream{Buffer: bytes.NewBufferString("hello")}
	output := &hashBorrowedStream{Buffer: new(bytes.Buffer)}
	err := runHashCommand(t, input, output, "hash", "sha256", "--input", "-", "--output", "-")
	require.NoError(t, err)
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
	assert.Equal(t, want, output.String())
	assert.False(t, input.closed, "borrowed stdin was closed")
	assert.False(t, output.closed, "borrowed stdout was closed")
	contents, err := os.ReadFile("-")
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(contents), "explicit streams changed the literal dash file")
}

func TestExampleHashReadsAndWritesFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	inputPath := filepath.Join(directory, "payload.bin")
	outputPath := filepath.Join(directory, "payload.sha256")
	payload := []byte("file payload\x00\xff")
	require.NoError(t, os.WriteFile(inputPath, payload, 0o600))

	stdout, err := executeHashCommand(
		t,
		bytes.NewReader(nil),
		"--input", inputPath, "hash", "sha256", "--output", outputPath,
	)
	require.NoError(t, err)
	assert.Empty(t, stdout, "stdout with file output")
	output, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	want := hex.EncodeToString(digest[:]) + "\n"
	assert.Equal(t, want, string(output), "output file")
}

type hashBorrowedStream struct {
	*bytes.Buffer
	closed bool
}

func (stream *hashBorrowedStream) Close() error {
	stream.closed = true
	return nil
}
