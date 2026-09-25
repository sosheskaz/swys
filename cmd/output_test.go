package cmd

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func TestKeyPublicMalformedBase64PreservesExistingOutput(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	privateBytes := []byte(privatePEM)
	for len(privateBytes)%3 == 0 {
		privateBytes = append(privateBytes, '\n')
	}
	encodedPrivate := base64.StdEncoding.EncodeToString(privateBytes)
	if !strings.HasSuffix(encodedPrivate, "=") {
		t.Fatalf("test setup produced unpadded base64 input %q", encodedPrivate)
	}

	rootCmd := newRootCmd()
	// A second padded segment decodes to whitespace, so the key parser accepts
	// it if the shared decoder mistakenly treats padding as a chunk delimiter.
	rootCmd.SetIn(&sequenceReader{chunks: [][]byte{[]byte(encodedPrivate), []byte("Cg==")}})
	outputPath := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = executeRootCommandStreams(
		t,
		rootCmd,
		"key", "public", "--input-encoding", "base64", "--output", outputPath,
	)
	if err == nil {
		t.Error("key public accepted base64 data after terminal padding")
	}
	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "preserve" {
		t.Fatalf("output after malformed input = %q, want preserved contents", got)
	}
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
			if err := os.WriteFile(inputPath, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if hardLink {
				outputPath = filepath.Join(directory, "alias")
				if err := os.Link(inputPath, outputPath); err != nil {
					t.Skipf("create hard link: %v", err)
				}
			}
			_, _, err := executeRootStreams(t, "hash", "sha256", "--input", inputPath, "--output", outputPath)
			if !errors.Is(err, commandio.ErrSameInputOutput) {
				t.Fatalf("error = %v, want errSameInputOutput", err)
			}
			contents, readErr := os.ReadFile(inputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(contents, original) {
				t.Fatalf("input = %q, want preserved contents", contents)
			}
		})
	}
}
