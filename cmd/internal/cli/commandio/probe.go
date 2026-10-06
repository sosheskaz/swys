package commandio

import "github.com/spf13/cobra"

// NewProbeRoot supplies shared persistent flags for a family-local completion
// probe without constructing the full CLI tree.
func NewProbeRoot() *cobra.Command {
	root := &cobra.Command{Use: "swys"}
	root.PersistentFlags().StringP("input", "i", "", "")
	root.PersistentFlags().StringP("output", "o", "", "")
	root.PersistentFlags().String("mode", "", "")
	return root
}
