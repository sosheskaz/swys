package http_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPBodyFileOpenFailureIsReported(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := executeRoot(t, "http", "-X", "POST", "--input", missing, "http://127.0.0.1:1")

	require.ErrorIs(t, err, os.ErrNotExist)
	assert.ErrorContains(t, err, "open HTTP body")
}
