package cmd

import (
	"encoding/pem"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/asym"
)

var certCmd = &cobra.Command{
	Aliases: []string{"cert", "certificate", "x.509"},
	Use:     "x509",
	Short:   "Deal with x.509 certificates",
	Run: func(cmd *cobra.Command, args []string) {
		// Get output format
		outputFormat := dieIfT(cmd.Flags().GetString("output-format"))
		formatter := dieIfT(GetCertFormatter(outputFormat))

		data := dieIfT(io.ReadAll(cmd.InOrStdin()))
		var certInfos []*asym.CertInfo

		remainder := data
		for len(remainder) > 0 {
			pemBlock, rest := pem.Decode(remainder)
			if pemBlock == nil {
				// No more PEM blocks found
				if len(certInfos) == 0 {
					// No certificates were found at all
					fmt.Fprintln(cmd.ErrOrStderr(), "no valid PEM certificates found")
					return
				}
				break
			}
			info := dieIfT(asym.NewCertInfoFromDER(pemBlock.Bytes))
			certInfos = append(certInfos, info)
			remainder = rest
		}

		if len(certInfos) == 1 {
			dieIf(formatter.Format(certInfos[0], cmd.OutOrStdout()))
		} else if len(certInfos) > 1 {
			dieIf(formatter.FormatMultiple(certInfos, cmd.OutOrStdout()))
		}
	},
}

func init() {
	rootCmd.AddCommand(certCmd)
}
