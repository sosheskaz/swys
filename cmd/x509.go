package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

const certificatePEMType = "CERTIFICATE"

var certCmd = compatibilityAliasCommand(structuredOutputCommand(&cobra.Command{
	Aliases: []string{"x509", "certificate", "x.509"},
	Use:     "cert",
	Short:   "Create, inspect, and retrieve X.509 certificates",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !compatibilityAliasInvoked(cmd) {
			return cmd.Help()
		}
		if _, err := fmt.Fprintf(
			cmd.ErrOrStderr(),
			"warning: npc %s is deprecated; use npc cert inspect\n",
			cmd.CalledAs(),
		); err != nil {
			return fmt.Errorf("write certificate alias deprecation warning: %w", err)
		}
		return runCertInspect(cmd, args)
	},
}, certFormatNames))

var certInspectCmd = structuredOutputCommand(&cobra.Command{
	Use:   "inspect",
	Short: "Inspect X.509 certificates",
	Args:  cobra.NoArgs,
	RunE:  runCertInspect,
}, certFormatNames)

func runCertInspect(cmd *cobra.Command, _ []string) error {
	formatter, err := certFormatterFromCommand(cmd)
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
	return formatCertificates(cmd, formatter, certInfos)
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
		if block.Type != certificatePEMType {
			return nil, fmt.Errorf("%w %q; expected %s", errUnexpectedPEMType, block.Type, certificatePEMType)
		}

		parsed, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certs = append(certs, parsed...)
	}
	if len(certs) == 0 {
		return nil, errNoPEMCertificates
	}
	return certs, nil
}

func init() {
	rootCmd.AddCommand(certCmd)
	certCmd.AddCommand(certInspectCmd)
}
