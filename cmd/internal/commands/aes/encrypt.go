package aes

import (
	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func newEncryptCmd() *cobra.Command {
	cmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use: "encrypt [plaintext]", Short: "Encrypt using OpenPGP or Tink streaming AES",
		Aliases: []string{"enc", "e"},
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := commandio.CommandInput(cmd, args)
			if err != nil {
				return err
			}
			op, ok := cmd.Context().Value(aesOperationContextKey{}).(*aesOperation)
			if !ok {
				return errAESOperation
			}
			if op.wire == wireOpenPGP {
				return crypter.EncryptOpenPGP(op.key, op.chunk, input, cmd.OutOrStdout())
			}
			return crypter.EncryptTink(op.primitive, input, cmd.OutOrStdout(), op.aad)
		},
	}, true)
	addKeyFlags(cmd)
	addAESWireFlags(cmd)
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}
