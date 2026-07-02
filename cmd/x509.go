package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/cryptool/internal/asym"
)

var certCmd = &cobra.Command{
	Aliases: []string{"cert", "certificate", "x.509"},
	Use:     "x509",
	Short:   "Inspect X.509 certificates",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		outputFormat, err := cmd.Flags().GetString("output-format")
		if err != nil {
			return fmt.Errorf("read output-format flag: %w", err)
		}
		formatter, err := getCertFormatter(outputFormat)
		if err != nil {
			return err
		}

		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("read certificate input: %w", err)
		}
		certs, err := parsePEMCertificates(data)
		if err != nil {
			return err
		}
		certInfos, err := asym.NewCertInfos(certs, &x509.VerifyOptions{
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}, true)
		if err != nil {
			return err
		}
		return formatCertificates(formatter, certInfos, cmd.OutOrStdout())
	},
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remainder := data
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		remainder = rest
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block type %q; expected CERTIFICATE", block.Type)
		}

		parsed, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certs = append(certs, parsed...)
	}
	if len(certs) == 0 {
		return nil, errors.New("no valid PEM certificates found")
	}
	return certs, nil
}

func init() {
	rootCmd.AddCommand(certCmd)
	certCmd.PersistentFlags().StringP("output-format", "F", "text", "structured output format (text, long, json, pem, chain, fullchain)")
}
