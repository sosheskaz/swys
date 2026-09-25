package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

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
		newNetPipeProcess(ctx, "net", "connect", address),
		newNetPipeProcess(ctx, "net", "listen", address, "--recv-only"),
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
	return testcmd.FileSHA256(t, path)
}
