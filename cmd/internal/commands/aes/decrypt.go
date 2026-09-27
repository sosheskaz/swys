package aes

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func newDecryptCmd() *cobra.Command {
	cmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use: "decrypt [ciphertext]", Short: "Decrypt OpenPGP or Tink streaming AES",
		Aliases: []string{"dec", "d"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			op, ok := cmd.Context().Value(aesOperationContextKey{}).(*aesOperation)
			if !ok {
				return errAESOperation
			}
			if op.wire == wireOpenPGP {
				return op.pgp.CopyTo(cmd.OutOrStdout())
			}
			if _, err := io.Copy(cmd.OutOrStdout(), op.tinkReader); err != nil {
				return fmt.Errorf("decrypt Tink stream: %w", err)
			}
			return nil
		},
	}, true)
	addKeyFlags(cmd)
	addAESWireFlags(cmd)
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}
