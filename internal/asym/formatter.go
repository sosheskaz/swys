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
	systemCertPoolErr  error
)

// getSystemCertPool returns a cached system certificate pool.
func getSystemCertPool() (*x509.CertPool, error) {
	systemCertPoolOnce.Do(func() {
		systemCertPool, systemCertPoolErr = x509.SystemCertPool()
	})
	return systemCertPool, systemCertPoolErr
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
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// CertInfo holds all relevant certificate information for formatting.
type CertInfo struct {
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	cert               *x509.Certificate
	VerifyError        string `json:"verify_error,omitempty"`
	publicKeyBase64    string
	SerialNumber       string `json:"serial_number"`
	Issuer             string `json:"issuer"`
	RemainingTime      string `json:"remaining_time"`
	signatureBase64    string
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	issuerCN           string
	Subject            string `json:"subject"`
	subjectCN          string
	SHA256Fingerprint  string            `json:"sha256_fingerprint"`
	KeyUsage           []string          `json:"key_usage,omitempty"`
	Chains             [][]ChainCertInfo `json:"chains,omitempty"`
	RawDER             []byte            `json:"-"`
	ExtKeyUsage        []string          `json:"ext_key_usage,omitempty"`
	IPAddresses        []string          `json:"ip_addresses"`
	DNSNames           []string          `json:"dns_names"`
	Verified           bool              `json:"verified"`
	IsCA               bool              `json:"is_ca"`
	IsExpired          bool              `json:"is_expired"`
}

// SignatureBase64 returns the base64-encoded signature (lazy-loaded).
func (c *CertInfo) SignatureBase64() string {
	if c.signatureBase64 == "" && c.cert != nil {
		c.signatureBase64 = base64.RawStdEncoding.EncodeToString(c.cert.Signature)
	}
	return c.signatureBase64
}

// PublicKeyBase64 returns the base64-encoded public key (lazy-loaded).
func (c *CertInfo) PublicKeyBase64() string {
	if c.publicKeyBase64 == "" && c.cert != nil {
		if pubkeyBytes, err := x509.MarshalPKIXPublicKey(c.cert.PublicKey); err == nil {
			c.publicKeyBase64 = base64.RawStdEncoding.EncodeToString(pubkeyBytes)
		}
	}
	return c.publicKeyBase64
}

// CertFormatter is the interface for certificate output formatters.
type CertFormatter interface {
	Format(info *CertInfo, w io.Writer) error
	FormatMultiple(infos []*CertInfo, w io.Writer) error
}

// NewCertInfo creates a CertInfo from an x509 certificate without verification.
func NewCertInfo(cert *x509.Certificate) (*CertInfo, error) {
	now := time.Now()
	remaining := cert.NotAfter.Sub(now)

	var remainingStr string
	if remaining < 0 {
		remainingStr = "expired"
	} else {
		remainingStr = formatDuration(remaining)
	}

	// Pre-compute serial number hex
	serialBytes := cert.SerialNumber.Bytes()
	serialHex := make([]byte, len(serialBytes)*2)
	for i, b := range serialBytes {
		serialHex[i*2] = "0123456789ABCDEF"[b>>4]
		serialHex[i*2+1] = "0123456789ABCDEF"[b&0x0f]
	}

	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       string(serialHex),
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

	// Pre-compute common names
	info.subjectCN = extractCN(info.Subject)
	info.issuerCN = extractCN(info.Issuer)

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

	return info, nil
}

// NewCertInfoVerified creates a CertInfo with verification status.
func NewCertInfoVerified(cert *x509.Certificate) (*CertInfo, error) {
	info, err := NewCertInfo(cert)
	if err != nil {
		return nil, err
	}

	certPool, err := getSystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}

	chains, verifyErr := cert.Verify(x509.VerifyOptions{
		Roots:       certPool,
		CurrentTime: time.Now(),
	})
	if verifyErr != nil {
		info.Verified = false
		info.VerifyError = verifyErr.Error()
	} else {
		info.Verified = true
		if len(chains) > 0 {
			info.Chains = make([][]ChainCertInfo, len(chains))
			for i, chain := range chains {
				info.Chains[i] = make([]ChainCertInfo, len(chain))
				for j, c := range chain {
					info.Chains[i][j] = ChainCertInfo{
						Subject: c.Subject.String(),
						Issuer:  c.Issuer.String(),
					}
				}
			}
		}
	}

	return info, nil
}

// NewCertInfoFromDER parses DER bytes and returns CertInfo with verification.
func NewCertInfoFromDER(der []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return NewCertInfoVerified(cert)
}

// extractCN extracts the Common Name attribute value from an RFC 2253
// distinguished name string, e.g. "CN=example.com,O=Acme,C=US" -> "example.com".
// The CN attribute may appear anywhere in the DN, not just first. A comma is
// only treated as an attribute separator when it isn't escaped with a
// backslash, since RFC 2253 allows commas inside attribute values that way.
// Returns the full DN unchanged if no CN attribute is found.
func extractCN(dn string) string {
	const prefix = "CN="
	for i := 0; i+len(prefix) <= len(dn); i++ {
		if i > 0 && dn[i-1] != ',' {
			continue
		}
		if dn[i:i+len(prefix)] != prefix {
			continue
		}

		start := i + len(prefix)
		for j := start; j < len(dn); j++ {
			if dn[j] == ',' && dn[j-1] != '\\' {
				return dn[start:j]
			}
		}
		return dn[start:]
	}
	return dn
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
