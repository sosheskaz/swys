package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/asym"
	"github.com/sosheskaz/swys/internal/netconn"
)

func newConnectCmd() *cobra.Command {
	cmd := commandio.NetworkCommand(commandio.StructuredOutputCommand(&cobra.Command{
		Aliases: []string{"c", "conn"},
		Use:     "connect host:port",
		Short:   "Fetch and display certificates from a TLS connection",
		RunE:    runPreparedInspection,
	}, certFormatNames))
	commandio.AddOutputEncodingFlag(cmd)
	addCertificateSelection(cmd, asym.SelectLeaf)
	addCertificateCAFlags(cmd)
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func validateCertConnectFlags(cmd *cobra.Command) error {
	if err := validateInspectionFlags(cmd); err != nil {
		return err
	}
	if err := validateCertificateCAFlags(cmd); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "ca")
}

func prepareConnectedCertificates(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
	address := cmd.Flags().Args()[0]
	dnsName, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address %q: %w", address, err)
	}
	timeout, err := cmd.Flags().GetDuration(commandio.ConnectTimeoutFlagName)
	if err != nil {
		return nil, fmt.Errorf("read connect-timeout flag: %w", err)
	}
	options := &x509.VerifyOptions{DNSName: dnsName}
	if err := addConnectVerificationRoots(cmd, options); err != nil {
		return nil, err
	}
	// Preparation precedes RunE, so its connection needs its own setup deadline.
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), timeout)
	defer cancel()
	connection, err := netconn.DialTLS(ctx, address, &tls.Config{
		// Retrieval and trust reporting are separate, including for private roots.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic retrieval reports verification separately
		ServerName:         dnsName,
	})
	if err != nil {
		return nil, err
	}
	defer connection.Close() //nolint:errcheck // peer certificates are already in memory
	certs := connection.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errNoPeerCertificates
	}
	return prepareInspection(cmd, certs, options, "peer")
}

// addConnectVerificationRoots keeps nil roots, and therefore the platform
// verifier, unless custom anchors were supplied; --system-ca alone is that default.
func addConnectVerificationRoots(cmd *cobra.Command, options *x509.VerifyOptions) error {
	caPath, err := cmd.Flags().GetString("ca")
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	caData, err := cmd.Flags().GetString(certCADataFlagName)
	if err != nil {
		return fmt.Errorf("read ca-data flag: %w", err)
	}
	if caPath == "" && caData == "" {
		return nil
	}
	options.Roots, err = certVerificationRoots(cmd)
	return err
}
