package cmd

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

func TestExampleCertificateSubjectCompletion(t *testing.T) {
	t.Parallel()

	values, directive := executeCertificateCompletion(t, "cert", "create", "--subject", "C")
	if !slices.Equal(values, []string{"CN=\tX.509 common name"}) {
		t.Fatalf("completions = %q, want CN= common-name suggestion", values)
	}
	wantDirective := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if directive != wantDirective {
		t.Fatalf("directive = %v, want no files and cursor continuation", directive)
	}
}
