package cmd

import (
	"crypto/aes"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/crypter"
)

var encryptCmd = &cobra.Command{
	Use:     "encrypt",
	Aliases: []string{"enc", "e"},
	Run: func(cmd *cobra.Command, args []string) {
		var input io.Reader
		if len(args) == 0 || args[0] == "-" {
			input = cmd.InOrStdin()
		} else {
			input = strings.NewReader(strings.Join(args, " "))
		}

		key := dieIfT(getKey(cmd))

		c := dieIfT(crypter.NewAESCrypter(key))

		iv := dieIfT(getIV(cmd, aes.BlockSize))
		dieIf(c.Encrypt(iv, input, cmd.OutOrStdout()))
	},
}

func init() {
	aesCmd.AddCommand(encryptCmd)

	addKeyFlags(encryptCmd)
	encryptCmd.Flags().BytesBase64("iv", []byte{}, "initialization vector to use for encryption, in base64. If not provided, a random IV will be generated.")
}

func getIV(cmd *cobra.Command, blockSize int) ([]byte, error) {
	ivFlag := cmd.Flags().Lookup("iv")
	if ivFlag.Changed {
		ivBase64, err := cmd.Flags().GetBytesBase64("iv")
		if err != nil {
			return nil, fmt.Errorf("failed to get iv: %w", err)
		}
		if len(ivBase64) != blockSize {
			return nil, fmt.Errorf("iv must be %d bytes long", blockSize)
		}
		return ivBase64, nil
	}
	return generateIV(blockSize), nil
}
