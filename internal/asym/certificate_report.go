package asym

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// Certificate selections are independent of the report's representation.
const (
	SelectLeaf      = "leaf"
	SelectChain     = "chain"
	SelectFullChain = "fullchain"
	SelectRoot      = "root"
)

// ErrCertificateSelection identifies an invalid or unavailable selection.
var ErrCertificateSelection = errors.New("certificate selection unavailable")

// CertificateReport separates retrieved certificate material from leaf verification.
type CertificateReport struct {
	Selection    string
	Certificates []*CertInfo
	Verification CertificateVerification
}

// CertificateVerification describes the original leaf, regardless of selection.
type CertificateVerification struct {
	chainNames [][]ChainCertInfo
	Error      string     `json:"error,omitempty"`
	Chains     [][]string `json:"chains"`
	Verified   bool       `json:"verified"`
}

// ValidateCertificateSelection checks selection before any input or output I/O.
func ValidateCertificateSelection(selection string) error {
	switch selection {
	case SelectLeaf, SelectChain, SelectFullChain, SelectRoot:
		return nil
	default:
		_, err := certificateIndex(selection)
		return err
	}
}

// InspectCertificates verifies the leaf before selecting certificates for export.
// source describes supplied material (peer or input); discovered roots retain
// verified_chain provenance instead of being presented as supplied material.
func InspectCertificates(certs []*x509.Certificate, options *x509.VerifyOptions, selection, source string) (*CertificateReport, error) {
	if err := ValidateCertificateSelection(selection); err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errEmptyCertChain
	}
	opts := x509.VerifyOptions{}
	if options != nil {
		opts = *options
	}
	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	} else {
		opts.Intermediates = opts.Intermediates.Clone()
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	leaf := NewCertInfo(certs[0])
	chains, err := verifyCertInfo(leaf, certs[0], &opts)
	if err != nil {
		return nil, fmt.Errorf("inspect leaf certificate: %w", err)
	}
	report := &CertificateReport{
		Selection: selection,
		Verification: CertificateVerification{
			Verified: leaf.Verified, Error: leaf.VerifyError, Chains: make([][]string, 0, len(chains)), chainNames: leaf.Chains,
		},
	}
	for _, chain := range chains {
		fingerprints := make([]string, 0, len(chain))
		for _, cert := range chain {
			fingerprints = append(fingerprints, NewCertInfo(cert).SHA256Fingerprint)
		}
		report.Verification.Chains = append(report.Verification.Chains, fingerprints)
	}
	selected, err := selectCertificates(certs, chains, selection)
	if err != nil {
		return nil, err
	}
	for _, cert := range selected {
		info := NewCertInfo(cert)
		certificateSource := "verified_chain"
		for _, supplied := range certs {
			if cert.Equal(supplied) {
				certificateSource = source
				break
			}
		}
		info.Source = certificateSource
		report.Certificates = append(report.Certificates, info)
	}
	return report, nil
}

func selectCertificates(supplied []*x509.Certificate, chains [][]*x509.Certificate, selection string) ([]*x509.Certificate, error) {
	switch selection {
	case SelectLeaf:
		return supplied[:1], nil
	case SelectFullChain:
		return supplied, nil
	case SelectChain:
		if len(supplied) > 1 {
			return supplied[1:], nil
		}
		return nil, fmt.Errorf("%w: no issuer certificates were supplied", ErrCertificateSelection)
	case SelectRoot:
		roots := verifiedRoots(chains)
		if len(roots) > 0 {
			return roots, nil
		}
		if suppliedRoot(supplied) {
			return supplied[len(supplied)-1:], nil
		}
		return nil, fmt.Errorf("%w: root unavailable; no verified chain or supplied leaf-first signature chain ending in a self-signed CA", ErrCertificateSelection)
	default:
		return selectCertificateIndex(supplied, chains, selection)
	}
}

func verifiedRoots(chains [][]*x509.Certificate) []*x509.Certificate {
	roots := make([]*x509.Certificate, 0, len(chains))
	seen := make(map[string]bool)
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		if !root.IsCA || seen[string(root.Raw)] {
			continue
		}
		seen[string(root.Raw)] = true
		roots = append(roots, root)
	}
	slices.SortFunc(roots, func(a, b *x509.Certificate) int {
		left, right := sha256.Sum256(a.Raw), sha256.Sum256(b.Raw)
		return bytes.Compare(left[:], right[:])
	})
	return roots
}

func suppliedRoot(certs []*x509.Certificate) bool {
	seen := make(map[string]bool)
	for i, cert := range certs {
		if seen[string(cert.Raw)] {
			return false
		}
		seen[string(cert.Raw)] = true
		if i > 0 && (!bytes.Equal(certs[i-1].RawIssuer, cert.RawSubject) || certs[i-1].CheckSignatureFrom(cert) != nil) {
			return false
		}
	}
	root := certs[len(certs)-1]
	return root.IsCA && bytes.Equal(root.RawSubject, root.RawIssuer) && root.CheckSignatureFrom(root) == nil
}

func certificateIndex(selection string) (int, error) {
	index, err := strconv.Atoi(selection)
	if err != nil || index < 0 {
		return 0, fmt.Errorf("%w: unknown selection %q (valid: leaf, chain, fullchain, root, or a non-negative decimal index)", ErrCertificateSelection, selection)
	}
	return index, nil
}

func selectCertificateIndex(supplied []*x509.Certificate, chains [][]*x509.Certificate, selection string) ([]*x509.Certificate, error) {
	index, err := certificateIndex(selection)
	if err != nil {
		return nil, err
	}
	chain := supplied
	if len(chains) > 0 {
		chain = chains[0]
		for _, candidate := range chains[1:] {
			if !slices.EqualFunc(chain, candidate, func(a, b *x509.Certificate) bool { return a.Equal(b) }) {
				return nil, fmt.Errorf("%w: numeric selection is ambiguous across multiple verified paths; use a named selection", ErrCertificateSelection)
			}
		}
		if len(chain) == 0 || !chain[len(chain)-1].IsCA {
			return nil, fmt.Errorf("%w: root CA unavailable for numeric selection", ErrCertificateSelection)
		}
	} else if !suppliedRoot(supplied) {
		return nil, fmt.Errorf("%w: root unavailable; numeric selection requires a complete root-to-leaf chain", ErrCertificateSelection)
	}
	if index >= len(chain) {
		return nil, fmt.Errorf("%w: index %d out of range (valid: 0..%d, root to leaf)", ErrCertificateSelection, index, len(chain)-1)
	}
	// Verification and TLS use leaf-first paths; the CLI indexes from the root.
	return []*x509.Certificate{chain[len(chain)-1-index]}, nil
}
