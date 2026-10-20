package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/asym"
	"github.com/sosheskaz/swys/internal/netconn"
)

const (
	certNoServerNameFlagName = "no-servername"
	certTLSMinFlagName       = "tls-min"
	certTLSMaxFlagName       = "tls-max"
)

var (
	certTLSVersions = map[string]uint16{
		"1.0": tls.VersionTLS10,
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
	certTLSVersionDescriptions = map[string]string{
		"1.0": "TLS 1.0 (legacy)",
		"1.1": "TLS 1.1 (legacy)",
		"1.2": "TLS 1.2",
		"1.3": "TLS 1.3",
	}
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
	cmd.Flags().String(tlsconfig.ServerNameFlagName, "", "TLS SNI and verification name (default endpoint host)")
	cmd.Flags().Bool(certNoServerNameFlagName, false, "send no SNI; verification uses the endpoint host")
	cmd.MarkFlagsMutuallyExclusive(tlsconfig.ServerNameFlagName, certNoServerNameFlagName)
	mustRegisterCertificateCompletion(cmd, tlsconfig.ServerNameFlagName, cobra.NoFileCompletions)
	cmd.Flags().String(tlsconfig.ALPNFlagName, "", "comma-separated TLS ALPN protocols to offer (default none)")
	mustRegisterCertificateCompletion(cmd, tlsconfig.ALPNFlagName, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return tlsconfig.CompleteALPN(toComplete)
	})
	cmd.Flags().String(certTLSMinFlagName, "", "minimum TLS version to offer: 1.0, 1.1, 1.2, or 1.3 (default 1.2)")
	cmd.Flags().String(certTLSMaxFlagName, "", "maximum TLS version to offer: 1.0, 1.1, 1.2, or 1.3 (default 1.3)")
	for _, name := range []string{certTLSMinFlagName, certTLSMaxFlagName} {
		commandio.RegisterDescribedFlagCompletion(cmd, name, func() []string {
			return slices.Sorted(maps.Keys(certTLSVersions))
		}, certTLSVersionDescriptions)
	}
	cmd.Flags().String(tlsconfig.CertFlagName, "", "TLS client certificate chain PEM path, or - for stdin")
	cmd.Flags().StringP(tlsconfig.KeyFlagName, "k", "", "TLS client private key path, or - for stdin")
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName} {
		if err := cmd.MarkFlagFilename(name); err != nil {
			panic(err)
		}
		mustRegisterCertificateCompletion(cmd, name, completeCertificateArtifact(name))
	}
	addCertificateArtifactEncodingFlags(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName)
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
	if _, err := connectHandshakeConfig(cmd); err != nil {
		return err
	}
	if err := validateConnectClientIdentity(cmd); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "ca", tlsconfig.CertFlagName, tlsconfig.KeyFlagName)
}

// connectHandshakeConfig parses the offered protocols and versions; unset
// versions keep crypto/tls client defaults.
func connectHandshakeConfig(cmd *cobra.Command) (*tls.Config, error) {
	alpn, err := cmd.Flags().GetString(tlsconfig.ALPNFlagName)
	if err != nil {
		return nil, fmt.Errorf("read alpn flag: %w", err)
	}
	protocols, err := tlsconfig.ParseALPN(alpn, errInvalidCertificateFlags)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{NextProtos: protocols}
	for _, version := range []struct {
		target *uint16
		name   string
	}{
		{target: &config.MinVersion, name: certTLSMinFlagName},
		{target: &config.MaxVersion, name: certTLSMaxFlagName},
	} {
		value, err := cmd.Flags().GetString(version.name)
		if err != nil {
			return nil, fmt.Errorf("read %s flag: %w", version.name, err)
		}
		if value == "" && !cmd.Flags().Changed(version.name) {
			continue
		}
		parsed, ok := certTLSVersions[value]
		if !ok {
			return nil, fmt.Errorf("%w: --%s %q (valid: 1.0, 1.1, 1.2, 1.3)", errInvalidCertificateFlags, version.name, value)
		}
		*version.target = parsed
	}
	// crypto/tls keeps its TLS 1.2 floor while MinVersion is unset.
	minimum := config.MinVersion
	if minimum == 0 {
		minimum = tls.VersionTLS12
	}
	if config.MaxVersion != 0 && minimum > config.MaxVersion {
		return nil, fmt.Errorf("%w: --%s (default 1.2) cannot exceed --%s", errInvalidCertificateFlags, certTLSMinFlagName, certTLSMaxFlagName)
	}
	return config, nil
}

func validateConnectClientIdentity(cmd *cobra.Command) error {
	certPath, err := cmd.Flags().GetString(tlsconfig.CertFlagName)
	if err != nil {
		return fmt.Errorf("read cert flag: %w", err)
	}
	keyPath, err := cmd.Flags().GetString(tlsconfig.KeyFlagName)
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if (certPath == "") != (keyPath == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", errInvalidCertificateFlags)
	}
	if err := validateCertificateArtifactEncodings(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName); err != nil {
		return err
	}
	var stdinOwners []string
	for _, name := range []string{"ca", tlsconfig.CertFlagName, tlsconfig.KeyFlagName} {
		path, err := cmd.Flags().GetString(name)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", name, err)
		}
		if path == "-" {
			stdinOwners = append(stdinOwners, "--"+name)
		}
	}
	if len(stdinOwners) > 1 {
		return fmt.Errorf("%w: only one of --ca, --cert, or --key can read stdin (got %s)", ErrCertificateInputSelection, strings.Join(stdinOwners, ", "))
	}
	return nil
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
	config, err := connectHandshakeConfig(cmd)
	if err != nil {
		return nil, err
	}
	// Retrieval and trust reporting are separate, including for private roots.
	config.InsecureSkipVerify = true
	config.ServerName = sni
	options := &x509.VerifyOptions{DNSName: verificationName}
	if err := addConnectVerificationRoots(cmd, options); err != nil {
		return nil, err
	}
	identity, hasIdentity, err := tlsconfig.ClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if hasIdentity {
		config.Certificates = []tls.Certificate{identity}
	}
	// Preparation precedes RunE, so its connection needs its own setup deadline.
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), timeout)
	defer cancel()
	connection, err := netconn.DialTLS(ctx, address, config)
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
