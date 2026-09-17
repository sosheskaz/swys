package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func newDecryptCmd() *cobra.Command {
	decryptCmd := binaryOutputCommand(&cobra.Command{
		Use:     "decrypt [ciphertext]",
		Short:   "Decrypt with AES-GCM by default or AES-CBC explicitly",
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
			mode, err := aesCipherModeFromCommand(cmd)
			if err != nil {
				return err
			}
			switch mode {
			case aesCipherModeGCM:
				cipher, err := crypter.NewAESGCMCrypter(key)
				if err != nil {
					return err
				}
				aad, err := aesAADFromCommand(cmd)
				if err != nil {
					return err
				}
				return cipher.Decrypt(input, cmd.OutOrStdout(), aad)
			case aesCipherModeCBC:
				cipher, err := crypter.NewAESCrypter(key)
				if err != nil {
					return err
				}
				return cipher.Decrypt(input, cmd.OutOrStdout())
			default:
				return fmt.Errorf("%w %q", errUnknownAESCipherMode, mode)
			}
		},
	}, true)
	addKeyFlags(decryptCmd)
	addAESCipherFlags(decryptCmd)
	decryptCmd.ValidArgsFunction = cobra.NoFileCompletions
	return decryptCmd
}
