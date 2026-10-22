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
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/asym"
	"github.com/sosheskaz/swys/internal/netconn"
)

const certNoServerNameFlagName = "no-servername"

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
	cmd.Flags().String(tlsconfig.ServerNameFlagName, "", "TLS SNI and verification name (default endpoint host)")
	cmd.Flags().Bool(certNoServerNameFlagName, false, "send no SNI; verification uses the endpoint host")
	cmd.MarkFlagsMutuallyExclusive(tlsconfig.ServerNameFlagName, certNoServerNameFlagName)
	mustRegisterCertificateCompletion(cmd, tlsconfig.ServerNameFlagName, cobra.NoFileCompletions)
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
	serverName, err := cmd.Flags().GetString(tlsconfig.ServerNameFlagName)
	if err != nil {
		return fmt.Errorf("read servername flag: %w", err)
	}
	if cmd.Flags().Changed(tlsconfig.ServerNameFlagName) && serverName == "" {
		return fmt.Errorf("%w: --servername requires a name; use --no-servername to omit SNI", errInvalidCertificateFlags)
	}
	return certinput.ValidatePaths(cmd, "ca")
}

func prepareConnectedCertificates(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
	address := cmd.Flags().Args()[0]
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address %q: %w", address, err)
	}
	sni, verificationName, err := connectServerNames(cmd, host)
	if err != nil {
		return nil, err
	}
	timeout, err := cmd.Flags().GetDuration(commandio.ConnectTimeoutFlagName)
	if err != nil {
		return nil, fmt.Errorf("read connect-timeout flag: %w", err)
	}
	options := &x509.VerifyOptions{DNSName: verificationName}
	if err := addConnectVerificationRoots(cmd, options); err != nil {
		return nil, err
	}
	// Preparation precedes RunE, so its connection needs its own setup deadline.
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), timeout)
	defer cancel()
	connection, err := netconn.DialTLS(ctx, address, &tls.Config{
		// Retrieval and trust reporting are separate, including for private roots.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic retrieval reports verification separately
		ServerName:         sni,
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

// connectServerNames returns the SNI to send and the name to verify; omitting
// SNI keeps verification on the endpoint host.
func connectServerNames(cmd *cobra.Command, host string) (string, string, error) {
	serverName, err := cmd.Flags().GetString(tlsconfig.ServerNameFlagName)
	if err != nil {
		return "", "", fmt.Errorf("read servername flag: %w", err)
	}
	omit, err := cmd.Flags().GetBool(certNoServerNameFlagName)
	if err != nil {
		return "", "", fmt.Errorf("read no-servername flag: %w", err)
	}
	switch {
	case omit:
		return "", host, nil
	case serverName != "":
		return serverName, serverName, nil
	default:
		return host, host, nil
	}
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
