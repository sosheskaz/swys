package aes

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func newAESKeygenCmd() *cobra.Command {
	cmd := commandio.SensitiveBinaryOutputCommand(&cobra.Command{
		Use:   "keygen",
		Short: "Generate a raw AES key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bits, err := cmd.Flags().GetInt("bits")
			if err != nil {
				return fmt.Errorf("read bits flag: %w", err)
			}
			return generateAESKey(bits, cmd.OutOrStdout())
		},
	}, false)
	cmd.Flags().IntP("bits", "b", 256, "AES key size in bits (128 or 256)")
	if err := cmd.RegisterFlagCompletionFunc("bits", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"128", "256"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func validateAESKeygenFlags(cmd *cobra.Command) error {
	bits, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return fmt.Errorf("read bits flag: %w", err)
	}
	return validateAESKeySize(bits)
}

func generateAESKey(bits int, output io.Writer) error {
	if err := validateAESKeySize(bits); err != nil {
		return err
	}
	if _, err := io.CopyN(output, rand.Reader, int64(bits/8)); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}
	return nil
}

func validateAESKeySize(bits int) error {
	switch bits {
	case 128, 256:
		return nil
	default:
		return fmt.Errorf("%w, got %d", crypter.ErrInvalidAESKeySize, bits)
	}
}
