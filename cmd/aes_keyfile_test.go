package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestAESRejectsKeyfileOutputCollisions(t *testing.T) { //nolint:paralleltest // literal-dash cases change the process working directory
	for _, leaf := range []string{"encrypt", "decrypt"} { //nolint:paralleltest // literal-dash subtests call t.Chdir
		for _, alias := range []string{"same path", "symlink", "hard link", "literal dash"} {
			t.Run(leaf+"/"+alias, func(t *testing.T) {
				dir := t.TempDir()
				keyfile := filepath.Join(dir, "key")
				if alias == "literal dash" {
					t.Chdir(dir)
					keyfile = "-"
				}
				key := bytes.Repeat([]byte{0x42}, 32)
				if err := os.WriteFile(keyfile, key, 0o600); err != nil {
					t.Fatal(err)
				}
				output := keyfile
				switch alias {
				case "symlink":
					output = filepath.Join(dir, "alias")
					if err := os.Symlink(keyfile, output); err != nil {
						if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) { // ERROR_PRIVILEGE_NOT_HELD
							t.Skipf("symlink creation requires privileges: %v", err)
						}
						t.Fatalf("create symlink: %v", err)
					}
				case "hard link":
					output = filepath.Join(dir, "alias")
					if err := os.Link(keyfile, output); err != nil {
						t.Fatalf("create hard link: %v", err)
					}
				}
				_, err := executeRoot(t, "aes", leaf, "payload", "--keyfile", keyfile, "--output", output)
				if err == nil {
					t.Error("expected keyfile/output collision error")
				}
				got, readErr := os.ReadFile(keyfile)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !bytes.Equal(got, key) {
					t.Errorf("keyfile changed: got %x, want %x", got, key)
				}
				if err != nil && !errors.Is(err, errAESKeyOutputCollision) {
					t.Errorf("error = %v, want keyfile/output collision", err)
				}
			})
		}
	}
}

func TestAESKeyfileRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "key")
	encrypted := filepath.Join(dir, "encrypted")
	if err := os.WriteFile(keyfile, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "aes", "encrypt", "hello", "--keyfile", keyfile, "--output", encrypted); err != nil {
		t.Fatal(err)
	}
	got, err := executeRoot(t, "aes", "decrypt", "--keyfile", keyfile, "--input", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("plaintext = %q, want hello", got)
	}
}

func TestAESKeyfilePathErrorPreservesOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(parent, "key")
	output := filepath.Join(dir, "output")
	original := []byte("preserve")
	if err := os.WriteFile(output, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeRoot(t, "aes", "encrypt", "hello", "--keyfile", keyfile, "--output", output)
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("error = %v, want source path error", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("output changed: %q", got)
	}
}
