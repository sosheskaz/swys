package testcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

// FileSHA256 returns the digest of a test fixture at path.
func FileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path) //nolint:gosec // callers pass paths in test-managed fixtures
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
