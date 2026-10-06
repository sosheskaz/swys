package cert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/asym"
)

const (
	defaultLeafValidityDays   = 30
	defaultCAValidityDays     = 365
	maxCertificateDays        = int(time.Duration(1<<63-1) / (24 * time.Hour))
	certificateRequestPEMType = "CERTIFICATE REQUEST"
	issuerCertFlagName        = "issuer-cert"
	issuerKeyFlagName         = "issuer-key"
	csrFlagName               = "csr"
)

func newCertCreateCmd() *cobra.Command {
	certCreateCmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use:   "create",
		Short: "Create a test or development X.509 certificate",
		Long: `Create a minimum-viable X.509 certificate for test and development use.

The default is a self-signed leaf valid for 30 days. Leaf subjects default to
the first --dns value, or CN=localhost. A server-capable leaf with no DNS/IP
SAN classifies its common name as a matching DNS or IP SAN. Leaves support
both TLS server and client authentication unless narrowed.

--ca creates a self-signed mini-CA valid for 365 days. --issuer-cert and
--issuer-key create a CA-signed leaf. Use --key to select existing private
material, including a key created with swys cert keygen.

swys never installs generated authorities into a trust store. Trust a generated
CA only in an explicitly selected test store, never system-wide.`,
		Args: cobra.NoArgs,
		RunE: runCertCreate,
	}, true)
	addCertificateIdentityFlags(certCreateCmd)
	certCreateCmd.Flags().Bool("ca", false, "create a self-signed test certificate authority")
	certCreateCmd.Flags().Int("days", 0, "validity in days (default 30 for leaves, 365 for CAs)")
	certCreateCmd.Flags().String(issuerCertFlagName, "", "issuer certificate path, or - for stdin")
	certCreateCmd.Flags().String(issuerKeyFlagName, "", "issuer private key path, or - for stdin")
	certCreateCmd.Flags().String(csrFlagName, "", "certificate signing request path, or - for stdin")
	certCreateCmd.Flags().Bool("server-only", false, "include only the TLS server-authentication usage")
	certCreateCmd.Flags().Bool("client-only", false, "include only the TLS client-authentication usage")
	for _, name := range []string{issuerCertFlagName, issuerKeyFlagName, csrFlagName} {
		if err := certCreateCmd.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	certCreateCmd.MarkFlagsRequiredTogether(issuerCertFlagName, issuerKeyFlagName)
	certCreateCmd.MarkFlagsMutuallyExclusive("server-only", "client-only")
	registerCertificateIdentityCompletions(certCreateCmd)
	registerCertificateCreateCompletions(certCreateCmd)
	addCertificateArtifactEncodingFlags(certCreateCmd, "key", csrFlagName, issuerCertFlagName, issuerKeyFlagName)

	return certCreateCmd
}

func newCertCSRCmd() *cobra.Command {
	certCSRCmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use:   csrFlagName,
		Short: "Create a PKCS #10 certificate signing request",
		Long: `Create a minimal PKCS #10 certificate signing request from an existing
private key. The request contains only its subject and requested DNS/IP SANs.
Its subject defaults to the first --dns value, or CN=localhost; with no subject
or SAN flags, localhost is also added as a DNS SAN. Submit the emitted request
to the intended CA, or sign it locally with swys cert create --csr and an issuer identity.`,
		Args: cobra.NoArgs,
		RunE: runCertCSR,
	}, true)
	addCertificateIdentityFlags(certCSRCmd)
	if err := certCSRCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	registerCertificateIdentityCompletions(certCSRCmd)
	addCertificateArtifactEncodingFlags(certCSRCmd, "key")
	return certCSRCmd
}

func runCertCreate(cmd *cobra.Command, _ []string) error {
	prepared, output, err := commandio.TakePrepared(cmd)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(prepared)); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

func prepareCertificateOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	if certificateCreateUsesCSR(cmd) {
		return prepareCertificateFromCSR(cmd, input)
	}
	options, err := certificateOptionsFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	subjectKey, err := certificateSubjectKeyFromCommand(cmd, input)
	if err != nil {
		return nil, err
	}
	issuer, issuerKey, err := certificateIssuerFromCommandInput(cmd, input)
	if err != nil {
		return nil, err
	}
	der, err := asym.CreateCertificate(&options, subjectKey, issuer, issuerKey)
	if err != nil {
		if issuer != nil {
			return nil, fmt.Errorf("create certificate using --issuer-cert and --issuer-key: %w", err)
		}
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: der}), nil
}

func certificateSubjectKeyFromCommand(cmd *cobra.Command, input io.Reader) (*asym.Key, error) {
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, fmt.Errorf("read key flag: %w", err)
	}
	key, err := readCertificateKey(cmd, input, "--key", keyPath)
	if err != nil {
		return nil, err
	}
	if _, err := key.Signer(); err != nil {
		return nil, fmt.Errorf("validate --key private signing material: %w", err)
	}
	return key, nil
}

func runCertCSR(cmd *cobra.Command, _ []string) error {
	prepared, output, err := commandio.TakePrepared(cmd)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(prepared)); err != nil {
		return fmt.Errorf("write certificate request: %w", err)
	}
	return nil
}

func prepareCertificateRequestOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	options, err := certificateRequestOptionsFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, fmt.Errorf("read key flag: %w", err)
	}
	key, err := readCertificateKey(cmd, input, "--key", keyPath)
	if err != nil {
		return nil, err
	}
	der, err := asym.CreateCertificateRequest(&options, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request from --key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: certificateRequestPEMType, Bytes: der}), nil
}

func validateCertificateCSRFlags(cmd *cobra.Command) error {
	if err := validateCertificateArtifactEncodings(cmd, "key"); err != nil {
		return err
	}
	if _, err := certificateRequestOptionsFromCommand(cmd); err != nil {
		return err
	}
	if err := validateCertificateKeySelection(cmd); err != nil {
		return err
	}
	if err := validateCertificateInputSelection(cmd, "key"); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "key")
}

func validateCertificateCreateFlags(cmd *cobra.Command) error {
	if err := validateCertificateArtifactEncodings(cmd, "key", csrFlagName, issuerCertFlagName, issuerKeyFlagName); err != nil {
		return err
	}
	csr, err := cmd.Flags().GetString(csrFlagName)
	if err != nil {
		return fmt.Errorf("read csr flag: %w", err)
	}
	if csr != "" {
		if err := validateCertificateCSRSelection(cmd); err != nil {
			return err
		}
		if err := validateCertificateIssuerSelection(cmd); err != nil {
			return err
		}
		if err := validateCertificateInputSelection(cmd, csrFlagName, issuerCertFlagName, issuerKeyFlagName); err != nil {
			return err
		}
		return certinput.ValidatePaths(cmd, csrFlagName, issuerCertFlagName, issuerKeyFlagName)
	}
	if _, err := certificateOptionsFromCommand(cmd); err != nil {
		return err
	}
	if err := validateCertificateKeySelection(cmd); err != nil {
		return err
	}
	if err := validateCertificateIssuerSelection(cmd); err != nil {
		return err
	}
	if err := validateCertificateInputSelection(cmd, "key", issuerCertFlagName, issuerKeyFlagName); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "key", issuerCertFlagName, issuerKeyFlagName)
}

func validateCertificateKeySelection(cmd *cobra.Command) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if key == "" {
		return fmt.Errorf("%w: --key must name a private key or -", errInvalidCertificateFlags)
	}
	return nil
}

func validateCertificateCSRSelection(cmd *cobra.Command) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if key != "" {
		return fmt.Errorf("%w: --csr cannot be combined with --key", errInvalidCertificateFlags)
	}
	ca, err := cmd.Flags().GetBool("ca")
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	if ca {
		return fmt.Errorf("%w: --csr cannot be combined with --ca", errInvalidCertificateFlags)
	}
	issuerCert, err := cmd.Flags().GetString(issuerCertFlagName)
	if err != nil {
		return fmt.Errorf("read issuer-cert flag: %w", err)
	}
	issuerKey, err := cmd.Flags().GetString(issuerKeyFlagName)
	if err != nil {
		return fmt.Errorf("read issuer-key flag: %w", err)
	}
	if issuerCert == "" || issuerKey == "" {
		return fmt.Errorf("%w: --csr requires --issuer-cert and --issuer-key", errInvalidCertificateFlags)
	}
	return nil
}

func validateCertificateIssuerSelection(cmd *cobra.Command) error {
	issuerCert, err := cmd.Flags().GetString(issuerCertFlagName)
	if err != nil {
		return fmt.Errorf("read issuer-cert flag: %w", err)
	}
	issuerKey, err := cmd.Flags().GetString(issuerKeyFlagName)
	if err != nil {
		return fmt.Errorf("read issuer-key flag: %w", err)
	}
	if !cmd.Flags().Changed(issuerCertFlagName) && !cmd.Flags().Changed(issuerKeyFlagName) {
		return nil
	}
	if issuerCert == "" || issuerKey == "" {
		return fmt.Errorf("%w: --issuer-cert and --issuer-key must both name a path or -", errInvalidCertificateFlags)
	}
	return nil
}

func certificateOptionsFromCommand(cmd *cobra.Command) (asym.CertificateOptions, error) {
	mode, err := certificateModeFromCommand(cmd)
	if err != nil {
		return asym.CertificateOptions{}, err
	}
	identity, err := certificateIdentityFromCommand(cmd, mode.isCA)
	if err != nil {
		return asym.CertificateOptions{}, err
	}
	days, err := certificateValidityDays(cmd, mode.isCA)
	if err != nil {
		return asym.CertificateOptions{}, err
	}
	if err := validateCertificateMode(mode, &identity); err != nil {
		return asym.CertificateOptions{}, err
	}
	if !mode.isCA && !mode.clientOnly && len(identity.DNSNames) == 0 && len(identity.IPAddresses) == 0 {
		if address := net.ParseIP(identity.Subject.CommonName); address != nil {
			identity.IPAddresses = []net.IP{address}
		} else {
			identity.DNSNames = []string{identity.Subject.CommonName}
		}
	}
	return asym.CertificateOptions{
		Subject:      identity.Subject,
		DNSNames:     identity.DNSNames,
		IPAddresses:  identity.IPAddresses,
		ExtKeyUsages: certificateExtKeyUsages(mode),
		ValidFor:     time.Duration(days) * 24 * time.Hour,
		IsCA:         mode.isCA,
	}, nil
}

type certificateMode struct {
	issuerCert string
	issuerKey  string
	isCA       bool
	serverOnly bool
	clientOnly bool
}

func certificateModeFromCommand(cmd *cobra.Command) (certificateMode, error) {
	mode := certificateMode{}
	var err error
	if mode.isCA, err = cmd.Flags().GetBool("ca"); err != nil {
		return certificateMode{}, fmt.Errorf("read ca flag: %w", err)
	}
	if mode.issuerCert, err = cmd.Flags().GetString(issuerCertFlagName); err != nil {
		return certificateMode{}, fmt.Errorf("read issuer-cert flag: %w", err)
	}
	if mode.issuerKey, err = cmd.Flags().GetString(issuerKeyFlagName); err != nil {
		return certificateMode{}, fmt.Errorf("read issuer-key flag: %w", err)
	}
	if mode.serverOnly, err = cmd.Flags().GetBool("server-only"); err != nil {
		return certificateMode{}, fmt.Errorf("read server-only flag: %w", err)
	}
	if mode.clientOnly, err = cmd.Flags().GetBool("client-only"); err != nil {
		return certificateMode{}, fmt.Errorf("read client-only flag: %w", err)
	}
	return mode, nil
}

func validateCertificateMode(mode certificateMode, identity *certificateIdentity) error {
	if !mode.isCA {
		return nil
	}
	if mode.issuerCert != "" || mode.issuerKey != "" {
		return fmt.Errorf("%w: --ca cannot be combined with issuer flags", errInvalidCertificateFlags)
	}
	if len(identity.DNSNames) != 0 || len(identity.IPAddresses) != 0 {
		return fmt.Errorf("%w: --ca cannot be combined with --dns or --ip", errInvalidCertificateFlags)
	}
	if mode.serverOnly || mode.clientOnly {
		return fmt.Errorf("%w: --ca cannot be combined with leaf authentication flags", errInvalidCertificateFlags)
	}
	return nil
}

func certificateExtKeyUsages(mode certificateMode) []x509.ExtKeyUsage {
	if mode.isCA {
		return nil
	}
	switch {
	case mode.serverOnly:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case mode.clientOnly:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
}

func certificateRequestOptionsFromCommand(cmd *cobra.Command) (asym.CertificateRequestOptions, error) {
	identity, err := certificateIdentityFromCommand(cmd, false)
	if err != nil {
		return asym.CertificateRequestOptions{}, err
	}
	if !cmd.Flags().Changed("subject") && len(identity.DNSNames) == 0 && len(identity.IPAddresses) == 0 {
		identity.DNSNames = []string{identity.Subject.CommonName}
	}
	return asym.CertificateRequestOptions{
		Subject:     identity.Subject,
		DNSNames:    identity.DNSNames,
		IPAddresses: identity.IPAddresses,
	}, nil
}

type certificateIdentity struct {
	Subject     pkix.Name
	DNSNames    []string
	IPAddresses []net.IP
}

func certificateIdentityFromCommand(cmd *cobra.Command, subjectRequired bool) (certificateIdentity, error) {
	dnsNames, err := cmd.Flags().GetStringArray("dns")
	if err != nil {
		return certificateIdentity{}, fmt.Errorf("read dns flag: %w", err)
	}
	for _, name := range dnsNames {
		if name == "" || name != strings.TrimSpace(name) {
			return certificateIdentity{}, fmt.Errorf("%w: --dns values must be non-empty and contain no surrounding whitespace", errInvalidCertificateFlags)
		}
	}
	ipTexts, err := cmd.Flags().GetStringArray("ip")
	if err != nil {
		return certificateIdentity{}, fmt.Errorf("read ip flag: %w", err)
	}
	ipAddresses := make([]net.IP, 0, len(ipTexts))
	for _, text := range ipTexts {
		address := net.ParseIP(text)
		if address == nil {
			return certificateIdentity{}, fmt.Errorf("%w: invalid --ip value %q", errInvalidCertificateFlags, text)
		}
		ipAddresses = append(ipAddresses, address)
	}

	subjectText, err := cmd.Flags().GetString("subject")
	if err != nil {
		return certificateIdentity{}, fmt.Errorf("read subject flag: %w", err)
	}
	if !cmd.Flags().Changed("subject") {
		if subjectRequired {
			return certificateIdentity{}, fmt.Errorf("%w: --subject is required with --ca", errInvalidCertificateFlags)
		}
		commonName := "localhost"
		if len(dnsNames) != 0 {
			commonName = dnsNames[0]
		}
		subjectText = "CN=" + commonName
	}
	subject, err := parseCommonNameSubject(subjectText)
	if err != nil {
		return certificateIdentity{}, err
	}
	return certificateIdentity{Subject: subject, DNSNames: dnsNames, IPAddresses: ipAddresses}, nil
}

func parseCommonNameSubject(text string) (pkix.Name, error) {
	if !strings.HasPrefix(text, "CN=") {
		return pkix.Name{}, fmt.Errorf("%w: --subject must use CN=<value>", errInvalidCertificateFlags)
	}
	commonName := strings.TrimPrefix(text, "CN=")
	if commonName == "" || commonName != strings.TrimSpace(commonName) {
		return pkix.Name{}, fmt.Errorf("%w: --subject common name must be non-empty and contain no surrounding whitespace", errInvalidCertificateFlags)
	}
	if strings.ContainsAny(commonName, ",+\x00\r\n") {
		return pkix.Name{}, fmt.Errorf("%w: --subject supports one CN component only", errInvalidCertificateFlags)
	}
	return pkix.Name{CommonName: commonName}, nil
}

func certificateValidityDays(cmd *cobra.Command, isCA bool) (int, error) {
	days := defaultLeafValidityDays
	if isCA {
		days = defaultCAValidityDays
	}
	if cmd.Flags().Changed("days") {
		value, err := cmd.Flags().GetInt("days")
		if err != nil {
			return 0, fmt.Errorf("read days flag: %w", err)
		}
		days = value
	}
	if days <= 0 || days > maxCertificateDays {
		return 0, fmt.Errorf("%w: --days must be between 1 and %d", errInvalidCertificateFlags, maxCertificateDays)
	}
	return days, nil
}

func validateCertificateInputSelection(cmd *cobra.Command, sourceFlags ...string) error {
	stdinOwners := 0
	for _, name := range sourceFlags {
		value, err := cmd.Flags().GetString(name)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", name, err)
		}
		if value == "-" {
			if cmd.Flags().Changed(commandio.InputEncodingFlagName) && cmd.Flags().Changed(name+"-encoding") {
				return fmt.Errorf("%w: --input-encoding and --%s-encoding select the same stream", ErrCertificateInputSelection, name)
			}
			stdinOwners++
		}
	}
	if stdinOwners > 1 {
		return fmt.Errorf("%w: at most one artifact flag may use -", ErrCertificateInputSelection)
	}
	if cmd.Flags().Changed("input") && stdinOwners != 1 {
		return fmt.Errorf("%w: --input requires one artifact flag set to -", ErrCertificateInputSelection)
	}
	if cmd.Flags().Changed(commandio.InputEncodingFlagName) && stdinOwners != 1 {
		return fmt.Errorf("%w: --input-encoding requires one artifact flag set to -", ErrCertificateInputSelection)
	}
	return nil
}

func readCertificateKey(cmd *cobra.Command, input io.Reader, flagName, source string) (*asym.Key, error) {
	data, err := readCertificateArtifactFrom(cmd, input, flagName, source, artifact.MaxKeyBytes)
	if err != nil {
		return nil, err
	}
	key, err := asym.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", flagName, err)
	}
	return key, nil
}

func addCertificateIdentityFlags(command *cobra.Command) {
	command.Flags().String("subject", "", "subject common name as CN=<value>")
	command.Flags().StringArray("dns", nil, "DNS subject alternative name (repeatable)")
	command.Flags().StringArray("ip", nil, "IP subject alternative name (repeatable)")
	command.Flags().StringP("key", "k", "", "existing private key path, or - for stdin")
	if err := command.MarkFlagFilename("key"); err != nil {
		panic(err)
	}
}
