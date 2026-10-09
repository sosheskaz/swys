package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/asym"
	"github.com/sosheskaz/swys/internal/pemstrict"
)

const (
	maxChainDiagnosticCertificates = 64
	certVerifyCommandName          = "verify"
	certIntermediatesFlagName      = "intermediates"
	certPurposeAny                 = "any"
	certPurposeServer              = "server"
	certPurposeClient              = "client"
)

var (
	// ErrCertificateReportNegative indicates a completed verification or matching report with a negative result.
	ErrCertificateReportNegative = errors.New("certificate report completed with a negative result")
	errCertificateChainOrder     = errors.New("input certificate chain is not leaf-first")
)

type certificateReportResultKey struct{}

type certificateReportResult struct{ negative bool }

type certificateReport struct { //nolint:govet // semantic field grouping keeps the custom text/JSON report readable
	Verified     bool `json:"-"`
	Match        bool `json:"-"`
	verifyReport bool
	Details      string            `json:"details"`
	Fingerprints map[string]string `json:"public_fingerprints"`
}

// MarshalJSON emits only the boolean appropriate to this report kind.
func (report certificateReport) MarshalJSON() ([]byte, error) {
	result := map[string]any{
		"details":             report.Details,
		"public_fingerprints": report.Fingerprints,
	}
	if report.verifyReport {
		result["verified"] = report.Verified
	} else {
		result["match"] = report.Match
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate report: %w", err)
	}
	return encoded, nil
}

func newCertVerifyCmd() *cobra.Command {
	command := commandio.StructuredOutputCommand(&cobra.Command{
		Use:   certVerifyCommandName,
		Short: "Verify an X.509 certificate chain",
		Args:  cobra.NoArgs,
		RunE:  runPreparedCertificateReport,
	}, certificateReportFormatNames)
	commandio.AddInputEncodingFlag(command)
	commandio.AddOutputEncodingFlag(command)
	addCertificateCAFlags(command)
	command.Flags().String(certIntermediatesFlagName, "", "PEM untrusted intermediate certificates path, or - for stdin")
	command.Flags().String("purpose", certPurposeServer, "verification purpose (server, client, any)")
	command.Flags().String("hostname", "", "DNS name or IP address to verify")
	command.Flags().String("at", "", "verification time in RFC 3339 format")
	if err := command.MarkFlagFilename(certIntermediatesFlagName); err != nil {
		panic(err)
	}
	commandio.RegisterDescribedFlagCompletion(command, "purpose", func() []string {
		return []string{certPurposeServer, certPurposeClient, certPurposeAny}
	}, map[string]string{
		certPurposeServer: "TLS server authentication (default)",
		certPurposeClient: "TLS client authentication",
		certPurposeAny:    "Any extended key usage",
	})
	for _, name := range []string{"at", "hostname"} {
		mustRegisterCertificateCompletion(command, name, cobra.NoFileCompletions)
	}
	addCertificateArtifactEncodingFlags(command, certIntermediatesFlagName)
	mustRegisterCertificateCompletion(command, certIntermediatesFlagName, completeCertificateArtifact(certIntermediatesFlagName))
	command.ValidArgsFunction = cobra.NoFileCompletions
	return command
}

func newCertMatchCmd() *cobra.Command {
	command := commandio.StructuredOutputCommand(&cobra.Command{
		Use:   "match",
		Short: "Compare public keys in certificates, keys, and CSRs",
		Args:  cobra.NoArgs,
		RunE:  runPreparedCertificateReport,
	}, certificateReportFormatNames)
	commandio.AddInputEncodingFlag(command)
	commandio.AddOutputEncodingFlag(command)
	command.Flags().String(tlsconfig.CertFlagName, "", "certificate path, or - for stdin")
	command.Flags().StringP(tlsconfig.KeyFlagName, "k", "", "public or private key path, or - for stdin")
	command.Flags().String(csrFlagName, "", "certificate request path, or - for stdin")
	command.ValidArgsFunction = cobra.NoFileCompletions
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	addCertificateArtifactEncodingFlags(command, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName)
	return command
}

func certificateReportFormatNames() []string { return []string{formatJSON, formatText} }

func runPreparedCertificateReport(cmd *cobra.Command, _ []string) error {
	prepared, output, err := commandio.TakePrepared(cmd)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(prepared)); err != nil {
		return fmt.Errorf("write certificate report: %w", err)
	}
	result, ok := cmd.Context().Value(certificateReportResultKey{}).(certificateReportResult)
	if !ok {
		return commandio.ErrPreparedOutputUnavailable
	}
	if result.negative {
		return ErrCertificateReportNegative
	}
	return nil
}

func validateCertVerifyFlags(cmd *cobra.Command) error {
	if err := validateCertificateCAFlags(cmd); err != nil {
		return err
	}
	if err := validateCertificateArtifactEncodings(cmd, certIntermediatesFlagName); err != nil {
		return err
	}
	if _, err := certVerificationPurpose(cmd); err != nil {
		return err
	}
	if _, err := certVerificationTime(cmd); err != nil {
		return err
	}
	if err := validateCertificateChainInputSelection(cmd, "ca", certIntermediatesFlagName); err != nil {
		return err
	}
	if err := certinput.ValidatePaths(cmd, "ca", certIntermediatesFlagName); err != nil {
		return err
	}
	format, err := cmd.Flags().GetString(commandio.FormatFlagName)
	if err != nil {
		return fmt.Errorf("read format flag: %w", err)
	}
	if format != formatText && format != formatJSON {
		return fmt.Errorf("%w %q (valid: json, text)", errUnknownCertFormat, format)
	}
	return nil
}

func validateCertMatchFlags(cmd *cobra.Command) error {
	if err := validateCertificateArtifactEncodings(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName); err != nil {
		return err
	}
	count := 0
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName} {
		value, err := cmd.Flags().GetString(name)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", name, err)
		}
		if value != "" {
			count++
		}
	}
	if count < 2 {
		return fmt.Errorf("%w: provide at least two of --cert, --key, and --csr", errInvalidCertificateFlags)
	}
	if err := validateCertificateInputSelection(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName); err != nil {
		return err
	}
	if err := certinput.ValidatePaths(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName); err != nil {
		return err
	}
	format, err := cmd.Flags().GetString(commandio.FormatFlagName)
	if err != nil {
		return fmt.Errorf("read format flag: %w", err)
	}
	if format != formatText && format != formatJSON {
		return fmt.Errorf("%w %q (valid: json, text)", errUnknownCertFormat, format)
	}
	return nil
}

func prepareCertificateReport(cmd *cobra.Command, input io.Reader, prepare func(*cobra.Command, io.Reader) (certificateReport, bool, error)) ([]byte, error) {
	report, positive, err := prepare(cmd, input)
	if err != nil {
		return nil, err
	}
	encoded, err := encodeCertificateReport(cmd, report)
	if err != nil {
		return nil, err
	}
	cmd.SetContext(context.WithValue(cmd.Context(), certificateReportResultKey{}, certificateReportResult{negative: !positive}))
	return encoded, nil
}

func prepareCertVerifyReport(cmd *cobra.Command, input io.Reader) (certificateReport, bool, error) {
	data, err := artifact.Read(input, artifact.MaxCertificateBytes)
	if err != nil {
		return certificateReport{}, false, fmt.Errorf("read certificate input: %w", err)
	}
	certificates, err := parseCertificateArtifact(data)
	if err != nil {
		return certificateReport{}, false, fmt.Errorf("parse certificate input: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	intermediatePath, err := cmd.Flags().GetString(certIntermediatesFlagName)
	if err != nil {
		return certificateReport{}, false, fmt.Errorf("read intermediates flag: %w", err)
	}
	if intermediatePath != "" {
		additional, readErr := readCertificateBundle(cmd, certIntermediatesFlagName, intermediatePath)
		if readErr != nil {
			return certificateReport{}, false, fmt.Errorf("read --intermediates: %w", readErr)
		}
		for _, certificate := range additional {
			intermediates.AddCert(certificate)
		}
	}
	options, err := certVerifyOptionsFromCommand(cmd, intermediates)
	if err != nil {
		return certificateReport{}, false, err
	}
	linkErr := validateSuppliedCertificateOrder(certificates)
	var verifyErr error
	if linkErr == nil {
		_, verifyErr = certificates[0].Verify(options)
	} else {
		options.Intermediates.AddCert(certificates[0])
		verifyErr = diagnoseSuppliedCertificateOrder(certificates, &options, linkErr)
	}
	verified := verifyErr == nil
	details := "certificate chain verified"
	if verifyErr != nil {
		details = verifyErr.Error()
	}
	report := certificateReport{
		Verified:     verified,
		verifyReport: true,
		Details:      details,
		Fingerprints: map[string]string{
			"certificate_sha256_fingerprint": fingerprint(certificates[0].Raw),
			"public_key_sha256_fingerprint":  publicKeyFingerprint(certificates[0].PublicKey),
		},
	}
	return report, verified, nil
}

func validateSuppliedCertificateOrder(certificates []*x509.Certificate) error {
	for index := range len(certificates) - 1 {
		child, issuer := certificates[index], certificates[index+1]
		if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
			return fmt.Errorf(
				"%w: certificate %d issuer does not name certificate %d",
				errCertificateChainOrder, index+1, index+2,
			)
		}
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf(
				"%w: certificate %d is not validly issued by certificate %d: %w",
				errCertificateChainOrder, index+1, index+2, err,
			)
		}
	}
	return nil
}

func diagnoseSuppliedCertificateOrder(
	certificates []*x509.Certificate,
	options *x509.VerifyOptions,
	orderedErr error,
) error {
	if len(certificates) > maxChainDiagnosticCertificates {
		return orderedErr
	}
	for _, candidate := range certificates {
		chains, err := candidate.Verify(*options)
		if err == nil && verifiedChainContainsSupplied(chains, certificates) {
			return fmt.Errorf(
				"%w: all supplied pieces form a valid chain but are in the wrong order",
				errCertificateChainOrder,
			)
		}
	}
	if defect := suppliedCertificateIssuerDefect(certificates); defect != nil {
		return defect
	}
	for candidateIndex, candidate := range certificates {
		if candidate.IsCA || !suppliedCertificatesFormChainFrom(certificates, candidateIndex) {
			continue
		}
		if _, err := candidate.Verify(*options); err != nil {
			return fmt.Errorf("verify reordered supplied chain: %w", err)
		}
	}
	return orderedErr
}

func suppliedCertificatesFormChainFrom(certificates []*x509.Certificate, candidateIndex int) bool {
	used := make([]bool, len(certificates))
	used[candidateIndex] = true
	current := certificates[candidateIndex]
	for range len(certificates) - 1 {
		found := false
		for issuerIndex, issuer := range certificates {
			if used[issuerIndex] || !bytes.Equal(current.RawIssuer, issuer.RawSubject) {
				continue
			}
			if err := current.CheckSignatureFrom(issuer); err != nil {
				continue
			}
			used[issuerIndex] = true
			current = issuer
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func verifiedChainContainsSupplied(chains [][]*x509.Certificate, supplied []*x509.Certificate) bool {
	for _, chain := range chains {
		remaining := make(map[string]int, len(chain))
		for _, certificate := range chain {
			remaining[string(certificate.Raw)]++
		}
		containsAll := true
		for _, certificate := range supplied {
			key := string(certificate.Raw)
			if remaining[key] == 0 {
				containsAll = false
				break
			}
			remaining[key]--
		}
		if containsAll && verifiedChainHasNoUnsuppliedNonterminal(chain, remaining) {
			return true
		}
	}
	return false
}

func verifiedChainHasNoUnsuppliedNonterminal(chain []*x509.Certificate, remaining map[string]int) bool {
	for _, certificate := range chain[:len(chain)-1] {
		if remaining[string(certificate.Raw)] > 0 {
			return false
		}
	}
	return true
}

func suppliedCertificateIssuerDefect(certificates []*x509.Certificate) error {
	for childIndex, child := range certificates {
		for issuerIndex, issuer := range certificates {
			if childIndex == issuerIndex || !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
				continue
			}
			if err := child.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf(
					"certificate %d signature or CA constraint is invalid for certificate %d: %w",
					childIndex+1, issuerIndex+1, err,
				)
			}
		}
	}
	return nil
}

func certVerifyOptionsFromCommand(cmd *cobra.Command, intermediates *x509.CertPool) (x509.VerifyOptions, error) {
	roots, err := certVerificationRoots(cmd)
	if err != nil {
		return x509.VerifyOptions{}, err
	}
	purpose, err := certVerificationPurpose(cmd)
	if err != nil {
		return x509.VerifyOptions{}, err
	}
	at, err := certVerificationTime(cmd)
	if err != nil {
		return x509.VerifyOptions{}, err
	}
	hostname, err := cmd.Flags().GetString("hostname")
	if err != nil {
		return x509.VerifyOptions{}, fmt.Errorf("read hostname flag: %w", err)
	}
	return x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: hostname,
		CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{purpose},
	}, nil
}

func prepareCertMatchReport(cmd *cobra.Command, input io.Reader) (certificateReport, bool, error) {
	fingerprints := make(map[string]string)
	canonical := make(map[string][]byte)
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName} {
		path, err := cmd.Flags().GetString(name)
		if err != nil {
			return certificateReport{}, false, fmt.Errorf("read %s flag: %w", name, err)
		}
		if path == "" {
			continue
		}
		der, err := readCertMatchPublicKey(cmd, input, name, path)
		if err != nil {
			return certificateReport{}, false, err
		}
		canonical[name] = der
		fingerprints[name+"_public_key_sha256_fingerprint"] = fingerprint(der)
	}
	matching := true
	var first []byte
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName} {
		der, ok := canonical[name]
		if !ok {
			continue
		}
		if first == nil {
			first = der
			continue
		}
		if !bytes.Equal(first, der) {
			matching = false
		}
	}
	details := "all supplied artifacts contain the same public key"
	if !matching {
		details = "supplied artifacts contain different public keys"
	}
	return certificateReport{Match: matching, Details: details, Fingerprints: fingerprints}, matching, nil
}

func readCertMatchPublicKey(cmd *cobra.Command, input io.Reader, name, path string) ([]byte, error) {
	limit := artifact.MaxKeyBytes
	if name == tlsconfig.CertFlagName {
		limit = artifact.MaxCertificateBytes
	}
	data, err := readCertificateEncodedOperand(cmd, input, name, path, limit)
	if err != nil {
		return nil, fmt.Errorf("read --%s: %w", name, err)
	}
	var public any
	switch name {
	case tlsconfig.CertFlagName:
		certificates, parseErr := parseCertificateArtifact(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse --cert: %w", parseErr)
		}
		public = certificates[0].PublicKey
	case tlsconfig.KeyFlagName:
		key, parseErr := asym.ParseKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse --key: %w", parseErr)
		}
		public, parseErr = key.Public()
		if parseErr != nil {
			return nil, fmt.Errorf("read --key public material: %w", parseErr)
		}
	case csrFlagName:
		request, parseErr := parseCertificateRequestArtifact(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse --csr: %w", parseErr)
		}
		if parseErr = request.CheckSignature(); parseErr != nil {
			return nil, fmt.Errorf("verify --csr signature: %w", parseErr)
		}
		public = request.PublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("canonicalize --%s public key: %w", name, err)
	}
	return der, nil
}

func certVerificationPurpose(cmd *cobra.Command) (x509.ExtKeyUsage, error) {
	value, err := cmd.Flags().GetString("purpose")
	if err != nil {
		return 0, fmt.Errorf("read purpose flag: %w", err)
	}
	switch value {
	case certPurposeServer:
		return x509.ExtKeyUsageServerAuth, nil
	case certPurposeClient:
		return x509.ExtKeyUsageClientAuth, nil
	case certPurposeAny:
		return x509.ExtKeyUsageAny, nil
	default:
		return 0, fmt.Errorf("%w: --purpose must be server, client, or any", errInvalidCertificateFlags)
	}
}

func certVerificationTime(cmd *cobra.Command) (time.Time, error) {
	value, err := cmd.Flags().GetString("at")
	if err != nil {
		return time.Time{}, fmt.Errorf("read at flag: %w", err)
	}
	if value == "" {
		return time.Now(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: parse --at as RFC 3339: %w", errInvalidCertificateFlags, err)
	}
	return parsed, nil
}

func readCertificateBundle(cmd *cobra.Command, name, path string) ([]*x509.Certificate, error) {
	// The main chain is a separate stream; supplemental stdin retains its own codec.
	decoder, err := certificateArtifactDecoder(cmd, name)
	if err != nil {
		return nil, err
	}
	data, err := artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), path, decoder, artifact.MaxCertificateBytes)
	if err != nil {
		return nil, err
	}
	return parseCertificateArtifact(data)
}

func parseCertificateArtifact(data []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return certinput.ParsePEMCertificates(trimmed)
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return []*x509.Certificate{certificate}, nil
}

func parseCertificateRequestArtifact(data []byte) (*x509.CertificateRequest, error) {
	trimmed := bytes.TrimSpace(data)
	der := data
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest := pemstrict.Decode(maskPEMHeaderBeginMarkers(trimmed))
		if block == nil || (block.Type != certificateRequestPEMType && block.Type != "NEW CERTIFICATE REQUEST") {
			return nil, fmt.Errorf("%w: expected CERTIFICATE REQUEST", certinput.ErrUnexpectedPEMType)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, certinput.ErrTrailingData
		}
		der = block.Bytes
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	return request, nil
}

func encodeCertificateReport(cmd *cobra.Command, report certificateReport) ([]byte, error) {
	format, err := cmd.Flags().GetString(commandio.FormatFlagName)
	if err != nil {
		return nil, fmt.Errorf("read format flag: %w", err)
	}
	if format == formatJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode certificate report: %w", err)
		}
		return append(encoded, '\n'), nil
	}
	var output strings.Builder
	if report.verifyReport {
		fmt.Fprintf(&output, "Verified: %t\n", report.Verified)
	} else {
		fmt.Fprintf(&output, "Match: %t\n", report.Match)
	}
	fmt.Fprintf(&output, "Details: %s\n", asym.EscapeDiagnosticValue(report.Details))
	fingerprintNames := []string{
		"certificate_sha256_fingerprint", "public_key_sha256_fingerprint",
		"cert_public_key_sha256_fingerprint", "key_public_key_sha256_fingerprint",
		"csr_public_key_sha256_fingerprint",
	}
	for _, name := range fingerprintNames {
		if value := report.Fingerprints[name]; value != "" {
			fmt.Fprintf(&output, "%s: %s\n", name, value)
		}
	}
	return []byte(output.String()), nil
}

func publicKeyFingerprint(public any) string {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "unavailable"
	}
	return fingerprint(der)
}

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for encoded != "" {
		parts = append(parts, encoded[:2])
		encoded = encoded[2:]
	}
	return strings.Join(parts, ":")
}
