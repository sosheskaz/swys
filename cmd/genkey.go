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
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		bits, err := cmd.Flags().GetInt("bits")
		if err != nil {
			return fmt.Errorf("read bits flag: %w", err)
		}
		switch bits {
		case 128, 192, 256:
		default:
			return fmt.Errorf("AES key size must be 128, 192, or 256 bits, got %d", bits)
		}

		if _, err := io.CopyN(cmd.OutOrStdout(), rand.Reader, int64(bits/8)); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		return nil
	},
}

func init() {
	aesCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().IntP("bits", "b", 128, "AES key size in bits (128, 192, or 256)")
}
