package cmd

import (
	"crypto/aes"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

var encryptCmd = binaryOutputCommand(&cobra.Command{
	Use:     "encrypt [plaintext]",
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
		cipher, err := crypter.NewAESCrypter(key)
		if err != nil {
			return err
		}
		iv, err := getIV(cmd, aes.BlockSize)
		if err != nil {
			return err
		}
		return cipher.Encrypt(iv, input, cmd.OutOrStdout())
	},
}, true)

func init() {
	aesCmd.AddCommand(encryptCmd)
	addKeyFlags(encryptCmd)
	encryptCmd.Flags().BytesBase64("iv", nil, "initialization vector as base64; random when omitted")
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
