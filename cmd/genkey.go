package cmd

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a new AES key",
	Run: func(cmd *cobra.Command, args []string) {
		bits, err := cmd.Flags().GetInt("bits")
		if err != nil {
			dieIf(fmt.Errorf("failed to get bits: %w", err))
		}
		if remainder := bits % 8; remainder != 0 {
			dieIf(fmt.Errorf("bits must be a multiple of 8, got %d (%d bytes, %d remained)", bits, bits/8, remainder))
		}
		keySize := int64(bits / 8)

		io.CopyN(cmd.OutOrStdout(), rand.Reader, keySize)
	},
}

func init() {
	aesCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().IntP("bits", "b", 128, "size of the AES key to generate, in bits (128, 192, 256).")
}
