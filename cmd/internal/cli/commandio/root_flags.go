package commandio

import "github.com/spf13/cobra"

// AddRootFlags registers the persistent flags used by the shared I/O lifecycle.
func AddRootFlags(root *cobra.Command) {
	root.PersistentFlags().StringP("input", "i", "", "redirect stdin from this file")
	if err := root.MarkPersistentFlagFilename("input"); err != nil {
		panic(err)
	}
	root.PersistentFlags().StringP("output", "o", "", "redirect stdout to this file")
	if err := root.MarkPersistentFlagFilename("output"); err != nil {
		panic(err)
	}
	root.PersistentFlags().String(
		"mode",
		"",
		"POSIX octal permissions for the --output file (e.g. 0640); explicitly overrides default, preserved, and sensitive-output permissions",
	)
}
