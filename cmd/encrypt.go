package cmd

import (
	"crypto/aes"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

var encryptCmd = binaryOutputCommand(&cobra.Command{
	Use:     "encrypt [plaintext]",
	Short:   "Encrypt with AES-GCM by default or AES-CBC explicitly",
	Aliases: []string{"enc", "e"},
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
			return cipher.Encrypt(input, cmd.OutOrStdout(), aad)
		case aesCipherModeCBC:
			cipher, err := crypter.NewAESCrypter(key)
			if err != nil {
				return err
			}
			iv, err := getIV(cmd, aes.BlockSize)
			if err != nil {
				return err
			}
			return cipher.Encrypt(iv, input, cmd.OutOrStdout())
		default:
			return fmt.Errorf("%w %q", errUnknownAESCipherMode, mode)
		}
	},
}, true)

func init() {
	aesCmd.AddCommand(encryptCmd)
	addKeyFlags(encryptCmd)
	addAESCipherFlags(encryptCmd)
	encryptCmd.Flags().BytesBase64("iv", nil, "CBC initialization vector as base64; random when omitted")
}

func getIV(cmd *cobra.Command, blockSize int) ([]byte, error) {
	ivFlag := cmd.Flags().Lookup("iv")
	if !ivFlag.Changed {
		return generateIV(blockSize)
	}

	iv, err := cmd.Flags().GetBytesBase64("iv")
	if err != nil {
		return nil, fmt.Errorf("read IV flag: %w", err)
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", crypter.ErrInvalidIVLength, blockSize, len(iv))
	}
	return iv, nil
}
