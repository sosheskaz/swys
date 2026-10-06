// Package certinput shares strict certificate input parsing and output collision checks.
package certinput

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sosheskaz/swys/internal/pemstrict"
)

// PEMType is the sole PEM block type accepted in certificate bundles.
const PEMType = "CERTIFICATE"

// Certificate input errors distinguish unexpected blocks, empty bundles, and framing failures.
var (
	ErrUnexpectedPEMType = errors.New("unexpected PEM block type")
	ErrNoCertificates    = errors.New("no valid PEM certificates found")
	ErrTrailingData      = errors.New("certificate input contains trailing data")
)

// ParsePEMCertificates requires a nonempty sequence of certificate PEM blocks,
// permitting whitespace between blocks but no other leading or trailing data.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remainder := bytes.TrimSpace(data)
	for len(remainder) > 0 {
		if !bytes.HasPrefix(remainder, []byte("-----BEGIN ")) {
			return nil, ErrTrailingData
		}
		block, rest := pemstrict.Decode(remainder)
		if block == nil {
			return nil, ErrTrailingData
		}
		if block.Type != PEMType {
			return nil, fmt.Errorf("%w %q; expected %s", ErrUnexpectedPEMType, block.Type, PEMType)
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certs = append(certs, parsed)
		remainder = bytes.TrimSpace(rest)
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}
	return certs, nil
}
