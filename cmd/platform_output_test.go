package cmd

import (
	"errors"
	"testing"

	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/securefile"
)

func writeOwnerOnlyFixture(t *testing.T, path, contents string) {
	t.Helper()
	file, err := securefile.OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(contents)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	testcmd.AssertPrivateOutput(t, path)
}

func assertWindowsModeRejection(t *testing.T, err error, path, contents string) {
	t.Helper()
	testcmd.AssertWindowsModeRejection(t, err, path, contents)
}
