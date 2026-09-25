//go:build !windows

package cert_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestCertificateCompletionDirectorySymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(directory, "linked-directory")
	require.NoError(t, os.Symlink(target, link))
	values, directive := executeCertificateCompletion(t, "cert", "create", "--key", link)
	if !certificateCompletionContains(values, link+string(filepath.Separator)) {
		t.Fatalf("completions = %q, want directory continuation for %s", values, link)
	}
	wantDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if directive != wantDirective {
		t.Fatalf("directive = %v, want %v", directive, wantDirective)
	}
}
