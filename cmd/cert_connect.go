package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/asym"
)

var connectCmd = &cobra.Command{
	Aliases: []string{"c", "conn"},
	Use:     "connect host:port",
	Short:   "Fetch and display certificates from a TLS connection",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		outputFormat, err := cmd.Flags().GetString("output-format")
		if err != nil {
			return fmt.Errorf("read output-format flag: %w", err)
		}
		formatter, err := getCertFormatter(outputFormat)
		if err != nil {
			return err
		}

		certs, dnsName, err := asym.CertFromDial(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		includeChain, err := cmd.Flags().GetBool("chain")
		if err != nil {
			return fmt.Errorf("read chain flag: %w", err)
		}
		includeChain = includeChain || formatter.RequiresChain()
		certInfos, err := asym.NewCertInfos(certs, &x509.VerifyOptions{DNSName: dnsName}, includeChain)
		if err != nil {
			return err
		}
		return formatCertificates(formatter, certInfos, cmd.OutOrStdout())
	},
}

func init() {
	certCmd.AddCommand(connectCmd)
	connectCmd.Flags().Bool("chain", false, "include the peer-provided certificate chain")
}
