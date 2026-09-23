package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testAESStreamHeaderSize       = 16
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
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := executeRoot(
		t,
		"aes", "encrypt", "--keyfile", keyPath,
		"--input", plaintextPath, "--output", ciphertextPath,
	); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(ciphertextPath)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x24}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := os.Create(plaintextPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := plaintext.Truncate(plaintextSize); err != nil {
		t.Fatal(errors.Join(err, plaintext.Close()))
	}
	if err := plaintext.Close(); err != nil {
		t.Fatal(err)
	}
	wantDigest := fileSHA256(t, plaintextPath)

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
	if gotDigest := fileSHA256(t, openedPath); gotDigest != wantDigest {
		t.Fatalf("opened plaintext SHA-256 = %q, want %q", gotDigest, wantDigest)
	}
}

//nolint:paralleltest // The greater-than-64-MiB process pipeline is intentionally serial to bound peak memory.
func TestExampleAESStreamingLargerThanSingleMessageThroughTCP(t *testing.T) {
	const plaintextSize = 64*1024*1024 + 1

	directory := t.TempDir()
	keyPath := filepath.Join(directory, "aes.key")
	plaintextPath := filepath.Join(directory, "payload.bin")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := os.Create(plaintextPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := plaintext.Truncate(plaintextSize); err != nil {
		t.Fatal(errors.Join(err, plaintext.Close()))
	}
	if err := plaintext.Close(); err != nil {
		t.Fatal(err)
	}
	wantDigest := fileSHA256(t, plaintextPath)

	address := unusedNetPipeAddress(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	commands := []*exec.Cmd{
		newNetPipeProcess(ctx, "aes", "encrypt", "--keyfile", keyPath, "--input", plaintextPath),
		newNetPipeProcess(ctx, "net", "connect", "tcp", address),
		newNetPipeProcess(ctx, "net", "listen", "tcp", address, "--recv-only"),
		newNetPipeProcess(ctx, "aes", "decrypt", "--keyfile", keyPath),
		newNetPipeProcess(ctx, "hash", "sha256"),
	}
	pipes := make([][2]*os.File, len(commands)-1)
	for i := range pipes {
		read, write, pipeErr := os.Pipe()
		if pipeErr != nil {
			closeNetPipeFiles(t, pipes[:i]...)
			t.Fatal(pipeErr)
		}
		pipes[i] = [2]*os.File{read, write}
	}
	t.Cleanup(func() { closeNetPipeFiles(t, pipes...) })
	for i := range len(commands) - 1 {
		commands[i].Stdout = pipes[i][1]
		commands[i+1].Stdin = pipes[i][0]
	}
	var gotDigest bytes.Buffer
	commands[len(commands)-1].Stdout = &gotDigest
	stderrs := make([]bytes.Buffer, len(commands))
	for i := range commands {
		commands[i].Stderr = &stderrs[i]
	}

	started := 0
	for i, command := range commands {
		if err := command.Start(); err != nil {
			stopNetPipeProcesses(commands[:started])
			t.Fatalf("start pipeline stage %d: %v", i, err)
		}
		started++
	}
	closeNetPipeFiles(t, pipes...)

	type stageResult struct {
		err   error
		index int
	}
	results := make(chan stageResult, len(commands))
	for i, command := range commands {
		go func() { results <- stageResult{index: i, err: command.Wait()} }()
	}
	stageErrors := make([]error, len(commands))
	for range commands {
		result := <-results
		stageErrors[result.index] = result.err
		if result.err != nil {
			cancel()
		}
	}
	if err := errors.Join(stageErrors...); err != nil {
		diagnostics := make([]string, len(commands))
		for i := range commands {
			diagnostics[i] = fmt.Sprintf("stage %d: error=%v stderr=%q", i, stageErrors[i], stderrs[i].String())
		}
		t.Fatalf("AES streaming TCP pipeline failed: %v (%s)", err, strings.Join(diagnostics, "; "))
	}
	if got := strings.TrimSpace(gotDigest.String()); got != wantDigest {
		t.Fatalf("received plaintext SHA-256 = %q, want %q", got, wantDigest)
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close digest input: %v", closeErr)
		}
	}()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
