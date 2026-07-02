package asym

import (
	"encoding/json"
	"io"
	"time"
)

// JSONFormatter formats certificate info as JSON.
type JSONFormatter struct {
	Indent bool // If true, pretty-print with indentation (default behavior)
}

// certInfoJSON is a JSON-serializable view of CertInfo that includes lazy-loaded fields.
type certInfoJSON struct {
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	SignatureBase64    string            `json:"signature_base64"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	SHA256Fingerprint  string            `json:"sha256_fingerprint"`
	SerialNumber       string            `json:"serial_number"`
	Issuer             string            `json:"issuer"`
	RemainingTime      string            `json:"remaining_time"`
	VerifyError        string            `json:"verify_error,omitempty"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	Subject            string            `json:"subject"`
	PublicKeyBase64    string            `json:"public_key_base64"`
	DNSNames           []string          `json:"dns_names"`
	KeyUsage           []string          `json:"key_usage,omitempty"`
	ExtKeyUsage        []string          `json:"ext_key_usage,omitempty"`
	Chains             [][]ChainCertInfo `json:"chains,omitempty"`
	IPAddresses        []string          `json:"ip_addresses"`
	IsCA               bool              `json:"is_ca"`
	Verified           bool              `json:"verified"`
	IsExpired          bool              `json:"is_expired"`
}

// toJSON converts CertInfo to its JSON-serializable form.
func (c *CertInfo) toJSON() *certInfoJSON {
	return &certInfoJSON{
		Subject:            c.Subject,
		Issuer:             c.Issuer,
		SerialNumber:       c.SerialNumber,
		DNSNames:           c.DNSNames,
		IPAddresses:        c.IPAddresses,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		RemainingTime:      c.RemainingTime,
		IsExpired:          c.IsExpired,
		SignatureAlgorithm: c.SignatureAlgorithm,
		SignatureBase64:    c.SignatureBase64(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm,
		PublicKeyBase64:    c.PublicKeyBase64(),
		IsCA:               c.IsCA,
		KeyUsage:           c.KeyUsage,
		ExtKeyUsage:        c.ExtKeyUsage,
		Verified:           c.Verified,
		VerifyError:        c.VerifyError,
		Chains:             c.Chains,
		SHA256Fingerprint:  c.SHA256Fingerprint,
	}
}

// Format writes a single certificate's info as JSON.
func (f *JSONFormatter) Format(info *CertInfo, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info.toJSON())
}

// FormatMultiple writes multiple certificates' info as a JSON array.
func (f *JSONFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	jsonInfos := make([]*certInfoJSON, len(infos))
	for i, info := range infos {
		jsonInfos[i] = info.toJSON()
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonInfos)
}
