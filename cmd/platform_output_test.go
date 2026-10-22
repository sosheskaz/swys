package cmd

import (
	"testing"

	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func writeOwnerOnlyFixture(t *testing.T, path, contents string) {
	t.Helper()
	testcmd.WriteOwnerOnlyFixture(t, path, contents)
}

func assertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	testcmd.AssertPrivateOutput(t, path)
}

func assertWindowsModeRejection(t *testing.T, err error, path, contents string) {
	t.Helper()
	testcmd.AssertWindowsModeRejection(t, err, path, contents)
}
