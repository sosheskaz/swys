package cmd

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

const (
	defaultLeafValidityDays = 30
	defaultCAValidityDays   = 365
	maxCertificateDays      = int((time.Duration(1<<63 - 1)) / (24 * time.Hour))
)

var certCreateCmd = binaryOutputCommand(&cobra.Command{
	Use:   "create",
	Short: "Create a test or development X.509 certificate",
	Long: `Create a minimum-viable X.509 certificate for test and development use.

The default is a self-signed leaf valid for 30 days. Leaf subjects default to
the first --dns value, or CN=localhost. A server-capable leaf with no DNS/IP
SAN classifies its common name as a matching DNS or IP SAN. Leaves support
both TLS server and client authentication unless narrowed.

--ca creates a self-signed mini-CA valid for 365 days. --issuer-cert and
--issuer-key create a CA-signed leaf. Use --key for existing private material,
or --key-out to generate a new Ed25519 PKCS #8 key without overwriting a path.

npc never installs generated authorities into a trust store. Trust a generated
CA only in an explicitly selected test store, never system-wide.`,
	Args: cobra.NoArgs,
	RunE: runCertCreate,
}, true)

var certCSRCmd = binaryOutputCommand(&cobra.Command{
	Use:   "csr",
	Short: "Create a PKCS #10 certificate signing request",
	Long: `Create a minimal PKCS #10 certificate signing request from an existing
private key. The request contains only its subject and requested DNS/IP SANs.
Its subject defaults to the first --dns value, or CN=localhost; with no subject
or SAN flags, localhost is also added as a DNS SAN. npc does not sign CSRs;
submit the emitted request to the intended CA.`,
	Args: cobra.NoArgs,
	RunE: runCertCSR,
}, true)

func runCertCreate(cmd *cobra.Command, _ []string) error {
	options, err := certificateOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	subjectKey, keyPEM, keyOut, err := certificateSubjectKeyFromCommand(cmd)
	if err != nil {
		return err
	}
	issuer, issuerKey, err := certificateIssuerFromCommand(cmd)
	if err != nil {
		return err
	}
	der, err := asym.CreateCertificate(&options, subjectKey, issuer, issuerKey)
	if err != nil {
		if issuer != nil {
			return fmt.Errorf("create certificate using --issuer-cert and --issuer-key: %w", err)
		}
		return fmt.Errorf("create certificate: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: der})
	return writeCreatedCertificate(cmd, certificatePEM, keyOut, keyPEM)
}

func certificateSubjectKeyFromCommand(cmd *cobra.Command) (*asym.Key, []byte, string, error) {
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, nil, "", fmt.Errorf("read key flag: %w", err)
	}
	keyOut, err := cmd.Flags().GetString("key-out")
	if err != nil {
		return nil, nil, "", fmt.Errorf("read key-out flag: %w", err)
	}
	if keyOut != "" {
		key, encoded, generateErr := generateCertificateKey()
		return key, encoded, keyOut, generateErr
	}
	key, err := readCertificateKey(cmd, "--key", keyPath)
	if err != nil {
		return nil, nil, "", err
	}
	if _, err := key.Signer(); err != nil {
		return nil, nil, "", fmt.Errorf("validate --key private signing material: %w", err)
	}
	return key, nil, "", nil
}

func certificateIssuerFromCommand(cmd *cobra.Command) (*x509.Certificate, *asym.Key, error) {
	issuerCertPath, err := cmd.Flags().GetString("issuer-cert")
	if err != nil {
		return nil, nil, fmt.Errorf("read issuer-cert flag: %w", err)
	}
	if issuerCertPath == "" {
		return nil, nil, nil
	}
	issuerKeyPath, err := cmd.Flags().GetString("issuer-key")
	if err != nil {
		return nil, nil, fmt.Errorf("read issuer-key flag: %w", err)
	}
	issuerData, err := readCertificateArtifact(cmd, "--issuer-cert", issuerCertPath)
	if err != nil {
		return nil, nil, err
	}
	issuer, err := parseSinglePEMCertificate(issuerData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse --issuer-cert: %w", err)
	}
	issuerKey, err := readCertificateKey(cmd, "--issuer-key", issuerKeyPath)
	if err != nil {
		return nil, nil, err
	}
	return issuer, issuerKey, nil
}

func writeCreatedCertificate(cmd *cobra.Command, certificatePEM []byte, keyOut string, keyPEM []byte) error {
	if keyOut != "" {
		if err := writeExclusivePrivateKey(keyOut, keyPEM); err != nil {
			return err
		}
		markRetainedCertificateKey(cmd, keyOut)
	}
	if _, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(certificatePEM)); err != nil {
		if keyOut != "" {
			return fmt.Errorf("write certificate; generated private key retained at %q: %w", keyOut, err)
		}
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

func runCertCSR(cmd *cobra.Command, _ []string) error {
	options, err := certificateRequestOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	key, err := readCertificateKey(cmd, "--key", keyPath)
	if err != nil {
		return err
	}
	der, err := asym.CreateCertificateRequest(&options, key)
	if err != nil {
		return fmt.Errorf("create certificate request from --key: %w", err)
	}
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(requestPEM)); err != nil {
		return fmt.Errorf("write certificate request: %w", err)
	}
	return nil
}

func validateCertFlagsBeforeIO(cmd *cobra.Command) error {
	switch cmd {
	case certCreateCmd:
		if _, err := certificateOptionsFromCommand(cmd); err != nil {
			return err
		}
		if err := validateCertificateKeySelection(cmd, true); err != nil {
			return err
		}
		if err := validateCertificateIssuerSelection(cmd); err != nil {
			return err
		}
		if err := validateCertificateInputSelection(cmd, "key", "issuer-cert", "issuer-key"); err != nil {
			return err
		}
		return validateCertificatePaths(cmd, "key-out", "key", "issuer-cert", "issuer-key")
	case certCSRCmd:
		if _, err := certificateRequestOptionsFromCommand(cmd); err != nil {
			return err
		}
		if err := validateCertificateKeySelection(cmd, false); err != nil {
			return err
		}
		if err := validateCertificateInputSelection(cmd, "key"); err != nil {
			return err
		}
		return validateCertificatePaths(cmd, "", "key")
	default:
		return nil
	}
}

func validateCertificateKeySelection(cmd *cobra.Command, allowKeyOut bool) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if !allowKeyOut {
		if key == "" {
			return fmt.Errorf("%w: --key must name a private key or -", errInvalidCertificateFlags)
		}
		return nil
	}
	keyOut, err := cmd.Flags().GetString("key-out")
	if err != nil {
		return fmt.Errorf("read key-out flag: %w", err)
	}
	if keyOut == "-" {
		return fmt.Errorf("%w: --key-out must name a file path, not -", errInvalidCertificateFlags)
	}
	if (key == "") == (keyOut == "") {
		return fmt.Errorf("%w: exactly one of --key or --key-out is required", errInvalidCertificateFlags)
	}
	return nil
}

func validateCertificateIssuerSelection(cmd *cobra.Command) error {
	issuerCert, err := cmd.Flags().GetString("issuer-cert")
	if err != nil {
		return fmt.Errorf("read issuer-cert flag: %w", err)
	}
	issuerKey, err := cmd.Flags().GetString("issuer-key")
	if err != nil {
		return fmt.Errorf("read issuer-key flag: %w", err)
	}
	if !cmd.Flags().Changed("issuer-cert") && !cmd.Flags().Changed("issuer-key") {
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
	if mode.issuerCert, err = cmd.Flags().GetString("issuer-cert"); err != nil {
		return certificateMode{}, fmt.Errorf("read issuer-cert flag: %w", err)
	}
	if mode.issuerKey, err = cmd.Flags().GetString("issuer-key"); err != nil {
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
			stdinOwners++
		}
	}
	if stdinOwners > 1 {
		return fmt.Errorf("%w: at most one artifact flag may use -", errCertificateInputSelection)
	}
	if cmd.Flags().Changed("input") && stdinOwners != 1 {
		return fmt.Errorf("%w: --input requires one artifact flag set to -", errCertificateInputSelection)
	}
	if cmd.Flags().Changed(inputEncodingFlagName) && stdinOwners != 1 {
		return fmt.Errorf("%w: --input-encoding requires one artifact flag set to -", errCertificateInputSelection)
	}
	return nil
}

func validateCertificatePaths(cmd *cobra.Command, keyOutFlag string, sourceFlags ...string) error {
	inputs, err := certificateInputPaths(cmd, sourceFlags)
	if err != nil {
		return err
	}
	outputs, err := certificateOutputPaths(cmd, keyOutFlag)
	if err != nil {
		return err
	}
	return rejectCertificatePathCollisions(inputs, outputs)
}

type namedCertificatePath struct {
	name string
	path string
}

func certificateInputPaths(cmd *cobra.Command, sourceFlags []string) ([]namedCertificatePath, error) {
	inputs := make([]namedCertificatePath, 0, len(sourceFlags)+1)
	for _, name := range sourceFlags {
		path, err := cmd.Flags().GetString(name)
		if err != nil {
			return nil, fmt.Errorf("read %s flag: %w", name, err)
		}
		if path != "" && path != "-" {
			inputs = append(inputs, namedCertificatePath{name: "--" + name, path: path})
		}
	}
	inputPath, err := cmd.Flags().GetString("input")
	if err != nil {
		return nil, fmt.Errorf("read input flag: %w", err)
	}
	if inputPath != "" {
		inputs = append(inputs, namedCertificatePath{name: "--input", path: inputPath})
	}
	return inputs, nil
}

func certificateOutputPaths(cmd *cobra.Command, keyOutFlag string) ([]namedCertificatePath, error) {
	outputs := make([]namedCertificatePath, 0, 2)
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, fmt.Errorf("read output flag: %w", err)
	}
	if outputPath != "" {
		outputs = append(outputs, namedCertificatePath{name: "--output", path: outputPath})
	}
	if keyOutFlag == "" {
		return outputs, nil
	}
	keyOut, err := cmd.Flags().GetString(keyOutFlag)
	if err != nil {
		return nil, fmt.Errorf("read %s flag: %w", keyOutFlag, err)
	}
	if keyOut == "" {
		return outputs, nil
	}
	if _, err := os.Lstat(keyOut); err == nil {
		return nil, fmt.Errorf("%w: %q", errKeyOutputExists, keyOut)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect --key-out %q: %w", keyOut, err)
	}
	return append(outputs, namedCertificatePath{name: "--key-out", path: keyOut}), nil
}

func rejectCertificatePathCollisions(inputs, outputs []namedCertificatePath) error {
	for _, input := range inputs {
		for _, output := range outputs {
			if err := rejectCertificatePathPair(input, output); err != nil {
				return err
			}
		}
	}
	for i, left := range outputs {
		for _, right := range outputs[i+1:] {
			if err := rejectCertificatePathPair(left, right); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectCertificatePathPair(left, right namedCertificatePath) error {
	same, err := sameCertificatePath(left.path, right.path)
	if err != nil {
		return err
	}
	if !same {
		return nil
	}
	return fmt.Errorf("%w: %s and %s refer to %q", errCertificatePathCollision, left.name, right.name, left.path)
}

func sameCertificatePath(left, right string) (bool, error) {
	leftCanonical, err := canonicalCertificatePath(left)
	if err != nil {
		return false, err
	}
	rightCanonical, err := canonicalCertificatePath(right)
	if err != nil {
		return false, err
	}
	if leftCanonical == rightCanonical {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(left)
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", left, leftErr)
	}
	rightInfo, rightErr := os.Stat(right)
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", right, rightErr)
	}
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}
	return false, nil
}

func canonicalCertificatePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return filepath.Clean(absolute), nil
		}
		return "", fmt.Errorf("resolve parent of path %q: %w", path, err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func readCertificateKey(cmd *cobra.Command, flagName, source string) (*asym.Key, error) {
	data, err := readCertificateArtifact(cmd, flagName, source)
	if err != nil {
		return nil, err
	}
	key, err := asym.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", flagName, err)
	}
	return key, nil
}

func readCertificateArtifact(cmd *cobra.Command, flagName, source string) ([]byte, error) {
	if source == "-" {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read %s from stdin: %w", flagName, err)
		}
		return data, nil
	}
	// The path is intentionally supplied by the CLI user.
	data, err := os.ReadFile(source) //nolint:gosec // reading an explicitly selected artifact is intended
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", flagName, source, err)
	}
	return data, nil
}

func parseSinglePEMCertificate(data []byte) (*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, errNoPEMCertificates
	}
	if block.Type != certificatePEMType {
		return nil, fmt.Errorf("%w %q; expected %s", errUnexpectedPEMType, block.Type, certificatePEMType)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errTrailingCertificateData
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PEM certificate: %w", err)
	}
	return cert, nil
}

func generateCertificateKey() (*asym.Key, []byte, error) {
	material, err := asym.GeneratePrivateKey(asym.KeyAlgorithmEd25519)
	if err != nil {
		return nil, nil, err
	}
	key, err := asym.NewKey(material)
	if err != nil {
		return nil, nil, fmt.Errorf("validate generated certificate key: %w", err)
	}
	encoded, err := key.Marshal(asym.KeyFormatPKCS8PEM)
	if err != nil {
		return nil, nil, err
	}
	return key, encoded, nil
}

func writeExclusivePrivateKey(path string, data []byte) error {
	// The path is intentionally supplied by the CLI user. Exclusive creation is the key-preservation contract.
	file, err := openExclusivePrivateKey(path)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %q", errKeyOutputExists, path)
		}
		return fmt.Errorf("create --key-out %q: %w", path, err)
	}
	cleanup := func(cause error, closeFile bool) error {
		var closeErr error
		if closeFile {
			closeErr = file.Close()
		}
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			removeErr = fmt.Errorf("remove partial --key-out %q: %w", path, removeErr)
		} else {
			removeErr = nil
		}
		return errors.Join(cause, closeErr, removeErr)
	}
	if _, err := io.Copy(file, bytes.NewReader(data)); err != nil {
		return cleanup(fmt.Errorf("write --key-out %q: %w", path, err), true)
	}
	if err := file.Close(); err != nil {
		return cleanup(fmt.Errorf("close --key-out %q: %w", path, err), false)
	}
	return nil
}

func addCertificateIdentityFlags(command *cobra.Command) {
	command.Flags().String("subject", "", "subject common name as CN=<value>")
	command.Flags().StringArray("dns", nil, "DNS subject alternative name (repeatable)")
	command.Flags().StringArray("ip", nil, "IP subject alternative name (repeatable)")
	command.Flags().String("key", "", "existing private key path, or - for stdin")
	if err := command.MarkFlagFilename("key"); err != nil {
		panic(err)
	}
}

func init() {
	certCmd.AddCommand(certCreateCmd, certCSRCmd)

	addCertificateIdentityFlags(certCreateCmd)
	certCreateCmd.Flags().Bool("ca", false, "create a self-signed test certificate authority")
	certCreateCmd.Flags().Int("days", 0, "validity in days (default 30 for leaves, 365 for CAs)")
	certCreateCmd.Flags().String("key-out", "", "write a new owner-only Ed25519 PKCS #8 private key (must not exist)")
	certCreateCmd.Flags().String("issuer-cert", "", "issuer certificate path, or - for stdin")
	certCreateCmd.Flags().String("issuer-key", "", "issuer private key path, or - for stdin")
	certCreateCmd.Flags().Bool("server-only", false, "include only the TLS server-authentication usage")
	certCreateCmd.Flags().Bool("client-only", false, "include only the TLS client-authentication usage")
	for _, name := range []string{"key-out", "issuer-cert", "issuer-key"} {
		if err := certCreateCmd.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	certCreateCmd.MarkFlagsOneRequired("key", "key-out")
	certCreateCmd.MarkFlagsMutuallyExclusive("key", "key-out")
	certCreateCmd.MarkFlagsRequiredTogether("issuer-cert", "issuer-key")
	certCreateCmd.MarkFlagsMutuallyExclusive("server-only", "client-only")

	addCertificateIdentityFlags(certCSRCmd)
	if err := certCSRCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
}
