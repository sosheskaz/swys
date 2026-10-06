package cmd

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

func TestKeyPublicMalformedBase64PreservesExistingOutput(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "cert", "keygen")
	require.NoError(t, err)
	privateBytes := []byte(privatePEM)
	for len(privateBytes)%3 == 0 {
		privateBytes = append(privateBytes, '\n')
	}
	encodedPrivate := base64.StdEncoding.EncodeToString(privateBytes)
	require.True(t, strings.HasSuffix(encodedPrivate, "="), "test setup produced unpadded base64 input %q", encodedPrivate)

	rootCmd := newRootCmd()
	// A second padded segment decodes to whitespace, so the key parser accepts
	// it if the shared decoder mistakenly treats padding as a chunk delimiter.
	rootCmd.SetIn(&sequenceReader{chunks: [][]byte{[]byte(encodedPrivate), []byte("Cg==")}})
	outputPath := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	_, _, err = executeRootCommandStreams(
		t,
		rootCmd,
		"cert", "key-public", "--input-encoding", "base64", "--output", outputPath,
	)
	if err == nil {
		t.Error("cert key-public accepted base64 data after terminal padding")
	}
	got, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(got), "output after malformed input")
}

type sequenceReader struct {
	err    error
	chunks [][]byte
}

func (r *sequenceReader) Read(buffer []byte) (int, error) {
	if len(r.chunks) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(buffer, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func TestHashRejectsSameFileAndHardLinkWithoutTruncation(t *testing.T) {
	t.Parallel()

	for _, hardLink := range []bool{false, true} {
		name := map[bool]string{false: "same path", true: "hard link"}[hardLink]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			inputPath := filepath.Join(directory, "input")
			outputPath := inputPath
			original := []byte("do not truncate")
			require.NoError(t, os.WriteFile(inputPath, original, 0o600))
			if hardLink {
				outputPath = filepath.Join(directory, "alias")
				if err := os.Link(inputPath, outputPath); err != nil {
					t.Skipf("create hard link: %v", err)
				}
			}
			_, _, err := executeRootStreams(t, "hash", "sha256", "--input", inputPath, "--output", outputPath)
			require.ErrorIs(t, err, commandio.ErrSameInputOutput)
			contents, readErr := os.ReadFile(inputPath)
			require.NoError(t, readErr)
			assert.Equal(t, original, contents, "input contents after rejection")
		})
	}
}
