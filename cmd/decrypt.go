package cmd

import (
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/crypter"
)

var decryptCmd = &cobra.Command{
	Use:     "decrypt",
	Aliases: []string{"dec", "d"},
	Run: func(cmd *cobra.Command, args []string) {
		var input io.Reader
		if len(args) == 0 || args[0] == "-" {
			input = cmd.InOrStdin()
		} else {
			input = strings.NewReader(strings.Join(args, " "))
		}

		key := dieIfT(getKey(cmd))
		c := dieIfT(crypter.NewAESCrypter(key))
		dieIf(c.Decrypt(input, cmd.OutOrStdout()))
	},
}

func init() {
	aesCmd.AddCommand(decryptCmd)
	addKeyFlags(decryptCmd)
}
