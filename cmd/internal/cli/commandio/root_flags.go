package commandio

import (
	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
)

// AddRootFlags registers the persistent flags used by the shared I/O lifecycle.
func AddRootFlags(root *cobra.Command) {
	presentation.AddFlags(root)
	root.PersistentFlags().StringP("input", "i", "", "read stdin from this file; use - for stdin")
	if err := root.MarkPersistentFlagFilename("input"); err != nil {
		panic(err)
	}
	root.PersistentFlags().StringP("output", "o", "", "write stdout to this file; use - for stdout")
	if err := root.MarkPersistentFlagFilename("output"); err != nil {
		panic(err)
	}
	root.PersistentFlags().String(
		"mode",
		"",
		"POSIX octal permissions for the --output file (e.g. 0640); explicitly overrides default, preserved, and sensitive-output permissions",
	)
}
