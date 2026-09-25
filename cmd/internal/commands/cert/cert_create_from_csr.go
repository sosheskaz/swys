package cert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/pemstrict"
)

var (
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

var (
	errEmptyCSR               = errors.New("certificate request is empty")
	errCSRPEMType             = errors.New("CSR PEM must contain one CERTIFICATE REQUEST block")
	errCSRPEMTrailing         = errors.New("CSR PEM contains trailing data")
	errCSRTrailing            = errors.New("certificate request contains trailing data")
	errCSRUnsupported         = errors.New("unsupported CSR requested extension")
	errCSRDuplicateSAN        = errors.New("duplicate CSR subject alternative name extension")
	errCSRMalformedSAN        = errors.New("unsupported malformed CSR subject alternative name extension")
	errCSRUnsupportedSANForm  = errors.New("unsupported CSR subject alternative name form")
	errCSRAmbiguousExtensions = errors.New("ambiguous CSR extension request attribute")
)

func prepareCertificateFromCSR(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	requestPath, err := cmd.Flags().GetString(csrFlagName)
	if err != nil {
		return nil, fmt.Errorf("read csr flag: %w", err)
	}
	requestData, err := readCertificateArtifactFrom(cmd, input, "--csr", requestPath, artifact.MaxKeyBytes)
	if err != nil {
		return nil, err
	}
	request, err := parseCertificateRequest(requestData)
	if err != nil {
		return nil, fmt.Errorf("parse --csr: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify --csr signature: %w", err)
	}
	if err := validateRawCertificateRequestExtensions(request); err != nil {
		return nil, err
	}
	if err := validateCertificateRequestExtensions(request); err != nil {
		return nil, err
	}
	options, err := certificateOptionsFromCSRCommand(cmd, request)
	if err != nil {
		return nil, err
	}
	issuer, issuerKey, err := certificateIssuerFromCommandInput(cmd, input)
	if err != nil {
		return nil, err
	}
	der, err := asym.CreateCertificateForPublicKey(&options, request.PublicKey, issuer, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate from --csr using --issuer-cert and --issuer-key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: der}), nil
}

func parseCertificateRequest(data []byte) (*x509.CertificateRequest, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errEmptyCSR
	}
	der := data
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, rest := pemstrict.Decode(maskPEMHeaderBeginMarkers(trimmed))
		if block == nil || (block.Type != certificateRequestPEMType && block.Type != "NEW CERTIFICATE REQUEST") {
			return nil, errCSRPEMType
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errCSRPEMTrailing
		}
		der = block.Bytes
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("certificate request: %w", err)
	}
	if !bytes.Equal(request.Raw, der) {
		return nil, errCSRTrailing
	}
	return request, nil
}

func maskPEMHeaderBeginMarkers(data []byte) []byte {
	masked := bytes.Clone(data)
	lineStart := bytes.IndexByte(masked, '\n') + 1
	if lineStart == 0 {
		return masked
	}
	for lineStart < len(masked) {
		lineEnd := bytes.IndexByte(masked[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(masked) - lineStart
		}
		line := masked[lineStart : lineStart+lineEnd]
		if len(bytes.TrimSpace(line)) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			break
		}
		value := line[colon+1:]
		for {
			marker := bytes.Index(value, []byte("-----BEGIN "))
			if marker < 0 {
				break
			}
			copy(value[marker:marker+len("-----BEGIN ")], "_____BEGIN ")
			value = value[marker+len("-----BEGIN "):]
		}
		lineStart += lineEnd + 1
	}
	return masked
}

func validateRawCertificateRequestExtensions(request *x509.CertificateRequest) error {
	var info struct { //nolint:govet // Field order is the signed PKCS #10 ASN.1 sequence.
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	rest, err := asn1.Unmarshal(request.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("inspect CSR extension requests: %w", errCSRAmbiguousExtensions)
	}
	extensionRequestCount := 0
	for _, raw := range info.RawAttributes {
		isExtensionRequest, valueCount, attributeErr := inspectRawCSRAttribute(raw)
		if !isExtensionRequest {
			continue
		}
		extensionRequestCount++
		if attributeErr != nil || extensionRequestCount > 1 || valueCount != 1 {
			return errCSRAmbiguousExtensions
		}
	}
	return nil
}

func inspectRawCSRAttribute(raw asn1.RawValue) (bool, int, error) {
	var sequence asn1.RawValue
	rest, ok := unmarshalCSRAttributeField(raw.FullBytes, &sequence)
	if !ok || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false, 0, nil
	}
	var id asn1.ObjectIdentifier
	valueDER, ok := unmarshalCSRAttributeField(sequence.Bytes, &id)
	if !ok || !id.Equal(oidExtensionRequest) {
		return false, 0, nil
	}
	var values asn1.RawValue
	rest, err := asn1.Unmarshal(valueDER, &values)
	if err != nil || len(rest) != 0 || values.Class != asn1.ClassUniversal || values.Tag != asn1.TagSet || !values.IsCompound {
		return true, 0, errCSRAmbiguousExtensions
	}
	count := 0
	for remaining := values.Bytes; len(remaining) != 0; count++ {
		var value asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &value)
		if err != nil {
			return true, 0, errCSRAmbiguousExtensions
		}
	}
	return true, count, nil
}

func unmarshalCSRAttributeField(data []byte, value any) ([]byte, bool) {
	rest, err := asn1.Unmarshal(data, value)
	return rest, err == nil
}

func validateCertificateRequestExtensions(request *x509.CertificateRequest) error {
	sanCount := 0
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(oidSubjectAltName) {
			return fmt.Errorf("%w %s", errCSRUnsupported, extension.Id.String())
		}
		sanCount++
		if sanCount > 1 {
			return errCSRDuplicateSAN
		}
		if err := validateCSRSubjectAltNames(extension); err != nil {
			return err
		}
	}
	return nil
}

func validateCSRSubjectAltNames(extension pkix.Extension) error {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(extension.Value, &names)
	if err != nil || len(rest) != 0 {
		return errCSRMalformedSAN
	}
	if len(names) == 0 {
		return errCSRMalformedSAN
	}
	for _, name := range names {
		if name.Class != asn1.ClassContextSpecific || name.IsCompound || (name.Tag != 2 && name.Tag != 7) {
			return errCSRUnsupportedSANForm
		}
	}
	return nil
}

func certificateOptionsFromCSRCommand(cmd *cobra.Command, request *x509.CertificateRequest) (asym.CertificateOptions, error) {
	mode, err := certificateModeFromCommand(cmd)
	if err != nil {
		return asym.CertificateOptions{}, err
	}
	days, err := certificateValidityDays(cmd, false)
	if err != nil {
		return asym.CertificateOptions{}, err
	}
	options := asym.CertificateOptions{
		Subject:      request.Subject,
		RawSubject:   request.RawSubject,
		DNSNames:     request.DNSNames,
		IPAddresses:  request.IPAddresses,
		ExtKeyUsages: certificateExtKeyUsages(mode),
		ValidFor:     time.Duration(days) * 24 * time.Hour,
	}
	if cmd.Flags().Changed("subject") {
		subjectText, err := cmd.Flags().GetString("subject")
		if err != nil {
			return asym.CertificateOptions{}, fmt.Errorf("read subject flag: %w", err)
		}
		options.Subject, err = parseCommonNameSubject(subjectText)
		if err != nil {
			return asym.CertificateOptions{}, err
		}
		options.RawSubject = nil
	}
	if cmd.Flags().Changed("dns") {
		options.DNSNames, err = validatedCertificateDNSFlags(cmd)
		if err != nil {
			return asym.CertificateOptions{}, err
		}
	}
	if cmd.Flags().Changed("ip") {
		options.IPAddresses, err = validatedCertificateIPFlags(cmd)
		if err != nil {
			return asym.CertificateOptions{}, err
		}
	}
	if emptyCertificateSubject(&options.Subject) && len(options.DNSNames) == 0 && len(options.IPAddresses) == 0 {
		return asym.CertificateOptions{}, fmt.Errorf("%w: final certificate identity has an empty subject and no DNS or IP SANs", errInvalidCertificateFlags)
	}
	return options, nil
}

func validatedCertificateDNSFlags(cmd *cobra.Command) ([]string, error) {
	values, err := cmd.Flags().GetStringArray("dns")
	if err != nil {
		return nil, fmt.Errorf("read dns flag: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: --dns values must be non-empty", errInvalidCertificateFlags)
	}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return nil, fmt.Errorf("%w: --dns values must be non-empty and contain no surrounding whitespace", errInvalidCertificateFlags)
		}
	}
	return values, nil
}

func validatedCertificateIPFlags(cmd *cobra.Command) ([]net.IP, error) {
	values, err := cmd.Flags().GetStringArray("ip")
	if err != nil {
		return nil, fmt.Errorf("read ip flag: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: --ip values must be non-empty", errInvalidCertificateFlags)
	}
	addresses := make([]net.IP, 0, len(values))
	for _, value := range values {
		address := net.ParseIP(value)
		if address == nil {
			return nil, fmt.Errorf("%w: invalid --ip value %q", errInvalidCertificateFlags, value)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func emptyCertificateSubject(subject *pkix.Name) bool {
	return len(subject.Names) == 0 && len(subject.ExtraNames) == 0 && subject.CommonName == "" &&
		len(subject.Organization) == 0 && len(subject.OrganizationalUnit) == 0 && len(subject.Country) == 0 &&
		len(subject.Province) == 0 && len(subject.Locality) == 0 && len(subject.StreetAddress) == 0 &&
		len(subject.PostalCode) == 0
}

func certificateIssuerFromCommandInput(cmd *cobra.Command, input io.Reader) (*x509.Certificate, *asym.Key, error) {
	issuerCertPath, err := cmd.Flags().GetString(issuerCertFlagName)
	if err != nil {
		return nil, nil, fmt.Errorf("read issuer-cert flag: %w", err)
	}
	issuerKeyPath, err := cmd.Flags().GetString(issuerKeyFlagName)
	if err != nil {
		return nil, nil, fmt.Errorf("read issuer-key flag: %w", err)
	}
	issuerData, err := readCertificateArtifactFrom(cmd, input, "--issuer-cert", issuerCertPath, artifact.MaxCertificateBytes)
	if err != nil {
		return nil, nil, err
	}
	issuers, err := certinput.ParsePEMCertificates(issuerData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse --issuer-cert: %w", err)
	}
	if len(issuers) != 1 {
		return nil, nil, fmt.Errorf("parse --issuer-cert: %w: issuer input must contain exactly one certificate, found %d", certinput.ErrTrailingData, len(issuers))
	}
	keyData, err := readCertificateArtifactFrom(cmd, input, "--issuer-key", issuerKeyPath, artifact.MaxKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	issuerKey, err := asym.ParseKey(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse --issuer-key: %w", err)
	}
	return issuers[0], issuerKey, nil
}

func readCertificateArtifactFrom(cmd *cobra.Command, input io.Reader, flagName, source string, limit int64) ([]byte, error) {
	if source == "-" {
		data, err := artifact.Read(input, limit)
		if err != nil {
			return nil, fmt.Errorf("read %s from stdin: %w", flagName, err)
		}
		return data, nil
	}
	return readCertificateArtifact(cmd, flagName, source, limit)
}
