package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPBodyFileOpenFailureIsReported(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := executeRoot(t, "http", "-X", "POST", "--input", missing, "http://127.0.0.1:1")

	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "open HTTP body") {
		t.Fatalf("error = %v, want the open failure named as the HTTP body", err)
	}
}
