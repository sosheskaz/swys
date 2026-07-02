package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/asym"
)

var connectCmd = &cobra.Command{
	Aliases: []string{"c", "conn"},
	Use:     "connect",
	Short:   "Fetch and display certificate from a TLS connection",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			dieIf(fmt.Errorf("expected exactly one argument, got %d", len(args)))
		}

		// Get output format
		outputFormat := dieIfT(cmd.Flags().GetString("output-format"))
		formatter := dieIfT(GetCertFormatter(outputFormat))

		certs := dieIfT(asym.CertFromDial(args[0]))

		// Determine which certs to include
		// For chain/fullchain formats, always include all certs
		// For other formats, respect the --chain flag
		var printCerts []*x509.Certificate
		if outputFormat == "chain" || outputFormat == "fullchain" {
			printCerts = certs
		} else if doChain, err := cmd.Flags().GetBool("chain"); err != nil {
			dieIf(fmt.Errorf("got unexpected error when looking up chain flag: %w", err))
		} else if doChain {
			printCerts = certs
		} else {
			printCerts = certs[:1]
		}

		// Convert to CertInfo
		certInfos := make([]*asym.CertInfo, len(printCerts))
		for i, cert := range printCerts {
			certInfos[i] = dieIfT(asym.NewCertInfoVerified(cert))
		}

		if len(certInfos) == 1 {
			dieIf(formatter.Format(certInfos[0], cmd.OutOrStdout()))
		} else {
			dieIf(formatter.FormatMultiple(certInfos, cmd.OutOrStdout()))
		}
	},
}

func init() {
	certCmd.AddCommand(connectCmd)
	connectCmd.Flags().Bool("chain", false, "print the entire cert chain, instead of just the immediate certificate.")
}
