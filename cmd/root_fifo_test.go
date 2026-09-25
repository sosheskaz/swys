//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func TestFIFOOutputStreamsDirectly(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "output.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		err  error
		data []byte
	}
	result := make(chan readResult, 1)
	go func() {
		data, err := os.ReadFile(path)
		result <- readResult{data: data, err: err}
	}()

	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", path); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-result:
		if read.err != nil {
			t.Fatal(read.err)
		}
		if len(read.data) != 32 {
			t.Fatalf("FIFO output length = %d, want 32", len(read.data))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading FIFO output")
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("output mode = %v, want named pipe", info.Mode())
	}
}

// TestOutputModeWithFIFORejectsBeforeWriting pins that --mode errors on a
// non-regular sink rather than silently ignoring it: npc never opens the
// FIFO in this case, so no reader goroutine is needed to unblock the write.
func TestOutputModeWithFIFORejectsBeforeWriting(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "output.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeRoot(t, "key", "generate", "ed25519", "--output", path, "--mode", "0640")
	if !errors.Is(err, commandio.ErrModeRequiresRegularOutput) {
		t.Fatalf("error = %v, want --mode-requires-regular-output", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("output mode = %v, want unchanged named pipe", info.Mode())
	}
}

// TestSymlinkToFIFOOutputStreamsDirectly pins --output paths like /dev/stdout
// or /dev/fd/N (process substitution), which are symlinks to non-regular files
// on Darwin and Linux.
func TestSymlinkToFIFOOutputStreamsDirectly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "output.fifo")
	linkPath := filepath.Join(dir, "output.link")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifoPath, linkPath); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	type readResult struct {
		err  error
		data []byte
	}
	result := make(chan readResult, 1)
	go func() {
		data, err := os.ReadFile(fifoPath)
		result <- readResult{data: data, err: err}
	}()

	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", linkPath); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-result:
		if read.err != nil {
			t.Fatal(read.err)
		}
		if len(read.data) != 32 {
			t.Fatalf("FIFO output length = %d, want 32", len(read.data))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading FIFO output")
	}

	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link mode = %v, want unchanged symlink", info.Mode())
	}
}
