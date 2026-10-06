package aes_test

import (
	"testing"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}
