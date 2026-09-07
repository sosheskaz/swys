package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/netconn"
)

func newConnectCmd() *cobra.Command {
	connectCmd := networkCommand(structuredOutputCommand(&cobra.Command{
		Aliases: []string{"c", "conn"},
		Use:     "connect host:port",
		Short:   "Fetch and display certificates from a TLS connection",
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter, err := certFormatterFromCommand(cmd)
			if err != nil {
				return err
			}

			dnsName, _, err := net.SplitHostPort(args[0])
			if err != nil {
				return fmt.Errorf("parse TLS address %q: %w", args[0], err)
			}
			connection, err := netconn.DialTLS(cmd.Context(), args[0], &tls.Config{
				// Verification remains a reporting concern so diagnostic inspection
				// can retrieve expired, mismatched, and privately trusted chains.
				InsecureSkipVerify: true, //nolint:gosec // diagnostic inspection intentionally reports trust failures after retrieval
				ServerName:         dnsName,
			})
			if err != nil {
				return err
			}
			defer connection.Close() //nolint:errcheck // peer certificates are already in memory
			certs := connection.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return errNoPeerCertificates
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
			return formatCertificates(cmd, formatter, certInfos)
		},
	}, certFormatNames))
	connectCmd.Flags().Bool("chain", false, "include the peer-provided certificate chain")
	return connectCmd
}
