package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestExampleHashSHA256FromStdin(t *testing.T) {
	t.Parallel()

	output, err := executeHashCommand(t, bytes.NewBufferString("hello"), "hash", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
	if string(output) != want {
		t.Fatalf("npc hash sha256 output = %q, want %q", output, want)
	}
}

func TestExampleHashReadsAndWritesFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	inputPath := filepath.Join(directory, "payload.bin")
	outputPath := filepath.Join(directory, "payload.sha256")
	payload := []byte("file payload\x00\xff")
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, err := executeHashCommand(
		t,
		bytes.NewReader(nil),
		"hash", "sha256", "--input", inputPath, "--output", outputPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(stdout) != 0 {
		t.Fatalf("stdout = %q, want file output only", stdout)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	want := hex.EncodeToString(digest[:]) + "\n"
	if string(output) != want {
		t.Fatalf("output file = %q, want %q", output, want)
	}
}
