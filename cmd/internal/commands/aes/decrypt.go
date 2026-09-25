package aes

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func newDecryptCmd() *cobra.Command {
	decryptCmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use:     "decrypt [ciphertext]",
		Short:   "Decrypt with AES-GCM by default or AES-CBC explicitly",
		Aliases: []string{"dec", "d"},
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := commandio.CommandInput(cmd, args)
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
				raw, err := cmd.Flags().GetBool("raw")
				if err != nil {
					return fmt.Errorf("read raw flag: %w", err)
				}
				aad, err := aesAADFromCommand(cmd)
				if err != nil {
					return err
				}
				if raw {
					cipher, err := crypter.NewAESGCMCrypter(key)
					if err != nil {
						return err
					}
					return cipher.Decrypt(input, cmd.OutOrStdout(), aad)
				}
				stream, err := crypter.NewAESStreamingCrypter(key)
				if err != nil {
					return err
				}
				return stream.Decrypt(input, cmd.OutOrStdout(), aad)
			case aesCipherModeCBC:
				cipher, err := crypter.NewAESCrypter(key)
				if err != nil {
					return err
				}
				return cipher.Decrypt(input, cmd.OutOrStdout())
			default:
				return fmt.Errorf("%w %q", ErrUnknownAESCipherMode, mode)
			}
		},
	}, true)
	addKeyFlags(decryptCmd)
	addAESCipherFlags(decryptCmd)
	decryptCmd.Flags().Bool("raw", false, "use legacy single-message AES-GCM format (64 MiB limit)")
	decryptCmd.ValidArgsFunction = cobra.NoFileCompletions
	return decryptCmd
}
