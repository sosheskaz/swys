package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

var decryptCmd = binaryOutputCommand(&cobra.Command{
	Use:     "decrypt [ciphertext]",
	Aliases: []string{"dec", "d"},
	RunE: func(cmd *cobra.Command, args []string) error {
		input, err := commandInput(cmd, args)
		if err != nil {
			return err
		}

		key, err := getKey(cmd)
		if err != nil {
			return err
		}
		cipher, err := crypter.NewAESCrypter(key)
		if err != nil {
			return err
		}
		return cipher.Decrypt(input, cmd.OutOrStdout())
	},
}, true)

func init() {
	aesCmd.AddCommand(decryptCmd)
	addKeyFlags(decryptCmd)
}
