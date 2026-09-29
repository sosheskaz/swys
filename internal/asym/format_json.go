package asym

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"time"
)

// JSONFormatter formats certificate info as JSON.
type JSONFormatter struct {
	Indent bool
}

// certificateMetadataJSON contains certificate fields independent of verification.
type certificateMetadataJSON struct {
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureBase64    string    `json:"signature_base64"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeySHA256    string    `json:"public_key_sha256_fingerprint"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	SerialNumber       string    `json:"serial_number"`
	Issuer             string    `json:"issuer"`
	RemainingTime      string    `json:"remaining_time"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Subject            string    `json:"subject"`
	PublicKeyBase64    string    `json:"public_key_base64"`
	DNSNames           []string  `json:"dns_names"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	IPAddresses        []string  `json:"ip_addresses"`
	IsCA               bool      `json:"is_ca"`
	IsExpired          bool      `json:"is_expired"`
}

type certInfoJSON struct {
	Chains      [][]ChainCertInfo `json:"chains,omitempty"`
	VerifyError string            `json:"verify_error,omitempty"`
	certificateMetadataJSON
	Verified bool `json:"verified"`
}

// toJSON converts CertInfo to its JSON-serializable form.
func (c *CertInfo) toJSON() (*certInfoJSON, error) {
	publicKey, err := c.PublicKeyBase64()
	if err != nil {
		return nil, err
	}
	publicKeyFingerprint, err := c.PublicKeySHA256Fingerprint()
	if err != nil {
		return nil, err
	}
	return &certInfoJSON{
		certificateMetadataJSON: certificateMetadataJSON{
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
			PublicKeyBase64:    publicKey,
			PublicKeySHA256:    publicKeyFingerprint,
			IsCA:               c.IsCA,
			KeyUsage:           c.KeyUsage,
			ExtKeyUsage:        c.ExtKeyUsage,
			SHA256Fingerprint:  c.SHA256Fingerprint,
		},
		Verified: c.Verified, VerifyError: c.VerifyError, Chains: c.Chains,
	}, nil
}

// Format writes a single certificate's info as JSON.
func (f *JSONFormatter) Format(info *CertInfo, w io.Writer) error {
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	jsonInfo, err := info.toJSON()
	if err != nil {
		return err
	}
	if err := encoder.Encode(jsonInfo); err != nil {
		return fmt.Errorf("encode certificate JSON: %w", err)
	}
	return nil
}

// FormatMultiple writes multiple certificates' info as a JSON array.
func (f *JSONFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	jsonInfos := make([]*certInfoJSON, len(infos))
	for i, info := range infos {
		jsonInfo, err := info.toJSON()
		if err != nil {
			return err
		}
		jsonInfos[i] = jsonInfo
	}
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(jsonInfos); err != nil {
		return fmt.Errorf("encode certificate JSON: %w", err)
	}
	return nil
}

// FormatReport writes a stable envelope even when only one certificate is selected.
func (f *JSONFormatter) FormatReport(report *CertificateReport, w io.Writer) error {
	certificates := make([]reportCertificateJSON, 0, len(report.Certificates))
	for _, info := range report.Certificates {
		metadata, err := info.toJSON()
		if err != nil {
			return err
		}
		certificates = append(certificates, reportCertificateJSON{
			certificateMetadataJSON: metadata.certificateMetadataJSON,
			PEM:                     string(pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: info.RawDER})),
			Source:                  info.Source,
		})
	}
	value := struct {
		Selection    string                  `json:"selection"`
		Certificates []reportCertificateJSON `json:"certificates"`
		Verification CertificateVerification `json:"verification"`
	}{report.Selection, certificates, report.Verification}
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode certificate report JSON: %w", err)
	}
	return nil
}

type reportCertificateJSON struct {
	PEM    string `json:"pem"`
	Source string `json:"source"`
	certificateMetadataJSON
}
