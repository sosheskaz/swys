package cmd

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Generate and inspect cryptographic keys",
}

var keyGenerateCmd = newKeyGenerateCommand("generate", 256, false)

// genkeyCmd is a one-release compatibility command for the former grammar.
var genkeyCmd = newKeyGenerateCommand("genkey", 128, true)

func newKeyGenerateCommand(use string, defaultBits int, deprecated bool) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: "Generate a new AES key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if deprecated {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is deprecated; use npc key generate\n", cmd.CommandPath()); err != nil {
					return fmt.Errorf("write genkey deprecation warning: %w", err)
				}
			}
			bits, err := cmd.Flags().GetInt("bits")
			if err != nil {
				return fmt.Errorf("read bits flag: %w", err)
			}
			return generateAESKey(bits, cmd.OutOrStdout())
		},
	}
	if deprecated {
		command.Hidden = true
		command.Long = "Deprecated: use npc key generate instead. This compatibility command will be removed in a future release."
	}

	command.Flags().IntP("bits", "b", defaultBits, "AES key size in bits (128, 192, or 256)")
	return binaryOutputCommand(command, false)
}

func generateAESKey(bits int, output io.Writer) error {
	switch bits {
	case 128, 192, 256:
	default:
		return fmt.Errorf("%w, got %d", errInvalidAESKeySize, bits)
	}
	if _, err := io.CopyN(output, rand.Reader, int64(bits/8)); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	aesCmd.AddCommand(genkeyCmd)
}
