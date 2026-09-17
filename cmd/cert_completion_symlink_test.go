//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestCertificateCompletionDirectorySymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked-directory")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	values, directive := executeCertificateCompletion(t, "cert", "create", "--key", link)
	if !certificateCompletionContains(values, link+string(filepath.Separator)) {
		t.Fatalf("completions = %q, want directory continuation for %s", values, link)
	}
	wantDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if directive != wantDirective {
		t.Fatalf("directive = %v, want %v", directive, wantDirective)
	}
}
