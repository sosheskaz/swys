package asym

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"
)

// Cached system cert pool - loaded once on first use.
var (
	systemCertPool     *x509.CertPool
	systemCertPoolOnce sync.Once
	errSystemCertPool  error
)

// getSystemCertPool returns a cached system certificate pool.
func getSystemCertPool() (*x509.CertPool, error) {
	systemCertPoolOnce.Do(func() {
		systemCertPool, errSystemCertPool = x509.SystemCertPool()
	})
	if errSystemCertPool != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", errSystemCertPool)
	}
	return systemCertPool, nil
}

// Package-level lookup tables to avoid allocation on each call.
var keyUsageNames = []struct {
	name string
	bit  x509.KeyUsage
}{
	{bit: x509.KeyUsageDigitalSignature, name: "Digital Signature"},
	{bit: x509.KeyUsageContentCommitment, name: "Content Commitment"},
	{bit: x509.KeyUsageKeyEncipherment, name: "Key Encipherment"},
	{bit: x509.KeyUsageDataEncipherment, name: "Data Encipherment"},
	{bit: x509.KeyUsageKeyAgreement, name: "Key Agreement"},
	{bit: x509.KeyUsageCertSign, name: "Certificate Sign"},
	{bit: x509.KeyUsageCRLSign, name: "CRL Sign"},
	{bit: x509.KeyUsageEncipherOnly, name: "Encipher Only"},
	{bit: x509.KeyUsageDecipherOnly, name: "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

// ChainCertInfo holds summarized info for certificates in a verification chain.
type ChainCertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	CommonName string `json:"-"`
}

// CertInfo holds all relevant certificate information for formatting.
//
// Field order satisfies govet's fieldalignment: pointer-dense types first,
// then strings, then slices, then the pointer-free bools. Ordering within each
// size class is unconstrained, so fields stay in reading order and unexported
// fields stay grouped. JSON output is unaffected either way -- certInfoJSON in
// format_json.go owns the wire format.
type CertInfo struct {
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	cert *x509.Certificate

	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	SerialNumber       string `json:"serial_number"`
	RemainingTime      string `json:"remaining_time"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	SHA256Fingerprint  string `json:"sha256_fingerprint"`
	VerifyError        string `json:"verify_error,omitempty"`

	subjectCN       string
	issuerCN        string
	signatureBase64 string
	publicKeyBase64 string

	DNSNames    []string          `json:"dns_names"`
	IPAddresses []string          `json:"ip_addresses"`
	KeyUsage    []string          `json:"key_usage,omitempty"`
	ExtKeyUsage []string          `json:"ext_key_usage,omitempty"`
	Chains      [][]ChainCertInfo `json:"chains,omitempty"`
	RawDER      []byte            `json:"-"`

	Verified  bool `json:"verified"`
	IsCA      bool `json:"is_ca"`
	IsExpired bool `json:"is_expired"`
}

// SignatureBase64 returns the base64-encoded signature (lazy-loaded).
func (c *CertInfo) SignatureBase64() string {
	if c.signatureBase64 == "" && c.cert != nil {
		c.signatureBase64 = base64.RawStdEncoding.EncodeToString(c.cert.Signature)
	}
	return c.signatureBase64
}

// PublicKeyBase64 returns the base64-encoded public key (lazy-loaded).
func (c *CertInfo) PublicKeyBase64() (string, error) {
	if c.publicKeyBase64 == "" && c.cert != nil {
		publicKey, err := x509.MarshalPKIXPublicKey(c.cert.PublicKey)
		if err != nil {
			return "", fmt.Errorf("marshal public key: %w", err)
		}
		c.publicKeyBase64 = base64.RawStdEncoding.EncodeToString(publicKey)
	}
	return c.publicKeyBase64, nil
}

// CertFormatter is the interface for certificate output formatters.
type CertFormatter interface {
	Format(info *CertInfo, w io.Writer) error
	FormatMultiple(infos []*CertInfo, w io.Writer) error
	RequiresChain() bool
}

// NewCertInfo creates a CertInfo from an X.509 certificate without verification.
func NewCertInfo(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	remaining := cert.NotAfter.Sub(now)

	var remainingStr string
	if remaining < 0 {
		remainingStr = "expired"
	} else {
		remainingStr = formatDuration(remaining)
	}

	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       fmt.Sprintf("%X", cert.SerialNumber),
		DNSNames:           cert.DNSNames, // Direct reference, no copy needed
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		RemainingTime:      remainingStr,
		IsExpired:          remaining < 0,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsCA:               cert.IsCA,
		RawDER:             cert.Raw,
		cert:               cert, // Keep for lazy loading
	}

	info.subjectCN = cert.Subject.CommonName
	if info.subjectCN == "" {
		info.subjectCN = info.Subject
	}
	info.issuerCN = cert.Issuer.CommonName
	if info.issuerCN == "" {
		info.issuerCN = info.Issuer
	}

	// IP addresses - only allocate if there are any
	if len(cert.IPAddresses) > 0 {
		info.IPAddresses = make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			info.IPAddresses[i] = ip.String()
		}
	}

	// Key usage - use pre-allocated capacity hint
	info.KeyUsage = keyUsageStrings(cert.KeyUsage)
	info.ExtKeyUsage = extKeyUsageStrings(cert.ExtKeyUsage)

	// SHA256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	info.SHA256Fingerprint = formatFingerprint(fingerprint[:])

	return info
}

// NewCertInfoVerified creates a CertInfo using the supplied verification options.
func NewCertInfoVerified(cert *x509.Certificate, options *x509.VerifyOptions) (*CertInfo, error) {
	info := NewCertInfo(cert)
	_, err := verifyCertInfo(info, cert, options)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func verifyCertInfo(
	info *CertInfo,
	cert *x509.Certificate,
	options *x509.VerifyOptions,
) ([][]*x509.Certificate, error) {
	verifyOptions := x509.VerifyOptions{}
	if options != nil {
		verifyOptions = *options
	}

	if verifyOptions.Roots == nil {
		certPool, poolErr := getSystemCertPool()
		if poolErr != nil {
			return nil, poolErr
		}
		verifyOptions.Roots = certPool
	}
	if verifyOptions.CurrentTime.IsZero() {
		verifyOptions.CurrentTime = time.Now()
	}

	chains, verifyErr := cert.Verify(verifyOptions)
	if verifyErr != nil {
		info.Verified = false
		info.VerifyError = verifyErr.Error()
	} else {
		info.Verified = true
		info.Chains = make([][]ChainCertInfo, len(chains))
		for i, chain := range chains {
			info.Chains[i] = make([]ChainCertInfo, len(chain))
			for j, chainCert := range chain {
				info.Chains[i][j] = ChainCertInfo{
					Subject:    chainCert.Subject.String(),
					Issuer:     chainCert.Issuer.String(),
					CommonName: chainCert.Subject.CommonName,
				}
			}
		}
	}
	return chains, nil
}

// NewCertInfos creates consistently verified information for a leaf-first certificate chain.
func NewCertInfos(certs []*x509.Certificate, options *x509.VerifyOptions, includeChain bool) ([]*CertInfo, error) {
	if len(certs) == 0 {
		return nil, errEmptyCertChain
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	certOptions := x509.VerifyOptions{}
	if options != nil {
		certOptions = *options
	}
	certOptions.Intermediates = intermediates
	leafInfo := NewCertInfo(certs[0])
	verifiedChains, err := verifyCertInfo(leafInfo, certs[0], &certOptions)
	if err != nil {
		return nil, fmt.Errorf("inspect leaf certificate: %w", err)
	}
	infos := []*CertInfo{leafInfo}
	if !includeChain {
		return infos, nil
	}

	for _, cert := range certs[1:] {
		info := NewCertInfo(cert)
		info.Verified = certificateInChains(cert, verifiedChains)
		infos = append(infos, info)
	}
	return infos, nil
}

func certificateInChains(cert *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		for _, verified := range chain {
			if cert.Equal(verified) {
				return true
			}
		}
	}
	return false
}

// NewCertInfoFromDER parses DER bytes and returns CertInfo with verification.
func NewCertInfoFromDER(der []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return NewCertInfoVerified(cert, nil)
}

// formatDuration formats a duration in a human-friendly way.
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days > 365 {
		years := days / 365
		remainingDays := days % 365
		return fmt.Sprintf("%dy%dd", years, remainingDays)
	}
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	minutes := int(d.Minutes())
	return fmt.Sprintf("%dm", minutes)
}

// Hex lookup table.
const hexChars = "0123456789ABCDEF"

// formatFingerprint formats a fingerprint as colon-separated hex.
func formatFingerprint(fp []byte) string {
	if len(fp) == 0 {
		return ""
	}
	result := make([]byte, len(fp)*3-1)
	for i, b := range fp {
		if i > 0 {
			result[i*3-1] = ':'
		}
		result[i*3] = hexChars[b>>4]
		result[i*3+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// keyUsageStrings converts KeyUsage bits to string slice.
func keyUsageStrings(usage x509.KeyUsage) []string {
	if usage == 0 {
		return nil
	}
	// Count bits first to allocate exact size
	count := 0
	for _, u := range keyUsageNames {
		if usage&u.bit != 0 {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	result := make([]string, 0, count)
	for _, u := range keyUsageNames {
		if usage&u.bit != 0 {
			result = append(result, u.name)
		}
	}
	return result
}

// extKeyUsageStrings converts ExtKeyUsage to string slice.
func extKeyUsageStrings(usage []x509.ExtKeyUsage) []string {
	if len(usage) == 0 {
		return nil
	}
	result := make([]string, 0, len(usage))
	for _, u := range usage {
		if name, ok := extKeyUsageNames[u]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return result
}

// CommonName returns the pre-computed subject common name.
func (c *CertInfo) CommonName() string {
	return c.subjectCN
}

// IssuerCommonName returns the pre-computed issuer common name.
func (c *CertInfo) IssuerCommonName() string {
	return c.issuerCN
}
