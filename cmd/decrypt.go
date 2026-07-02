package cmd

import (
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/crypter"
)

var decryptCmd = &cobra.Command{
	Use:     "decrypt [ciphertext]",
	Aliases: []string{"dec", "d"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var input io.Reader
		if len(args) == 0 || args[0] == "-" {
			input = cmd.InOrStdin()
		} else {
			input = strings.NewReader(strings.Join(args, " "))
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
}

func init() {
	aesCmd.AddCommand(decryptCmd)
	addKeyFlags(decryptCmd)
}
