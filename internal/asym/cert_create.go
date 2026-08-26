package asym

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

const certificateClockSkew = 5 * time.Minute

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// CertificateOptions describes one minimum-viable test certificate.
type CertificateOptions struct {
	Subject      pkix.Name
	DNSNames     []string
	IPAddresses  []net.IP
	ExtKeyUsages []x509.ExtKeyUsage
	ValidFor     time.Duration
	IsCA         bool
}

// CertificateRequestOptions describes one minimum-viable PKCS #10 request.
type CertificateRequestOptions struct {
	Subject     pkix.Name
	DNSNames    []string
	IPAddresses []net.IP
}

// CreateCertificate creates a self-signed certificate or an issuer-signed leaf.
func CreateCertificate(
	options *CertificateOptions,
	subjectKey *Key,
	issuer *x509.Certificate,
	issuerKey *Key,
) ([]byte, error) {
	return createCertificateAt(options, subjectKey, issuer, issuerKey, time.Now().UTC(), rand.Reader)
}

func createCertificateAt(
	options *CertificateOptions,
	subjectKey *Key,
	issuer *x509.Certificate,
	issuerKey *Key,
	now time.Time,
	random io.Reader,
) ([]byte, error) {
	if err := validateCertificateOptions(options, issuer, issuerKey); err != nil {
		return nil, err
	}

	subjectSigner, err := subjectKey.Signer()
	if err != nil {
		return nil, fmt.Errorf("access subject private key: %w", err)
	}
	subjectPublic, err := subjectKey.Public()
	if err != nil {
		return nil, fmt.Errorf("derive subject public key: %w", err)
	}
	serial, err := randomSerialNumber(random)
	if err != nil {
		return nil, err
	}

	now = now.UTC().Truncate(time.Second)
	template := certificateTemplate(options, subjectPublic, serial, now)
	parent, signer, err := certificateParentAndSigner(template, subjectSigner, issuer, issuerKey, now)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(random, template, parent, subjectPublic, signer)
	if err != nil {
		return nil, fmt.Errorf("create X.509 certificate: %w", err)
	}
	return der, nil
}

func validateCertificateOptions(
	options *CertificateOptions,
	issuer *x509.Certificate,
	issuerKey *Key,
) error {
	if options == nil {
		return fmt.Errorf("%w: options are nil", ErrInvalidCertificateOptions)
	}
	if options.Subject.CommonName == "" {
		return fmt.Errorf("%w: subject common name is empty", ErrInvalidCertificateOptions)
	}
	if options.ValidFor <= 0 {
		return fmt.Errorf("%w: validity must be positive", ErrInvalidCertificateOptions)
	}
	if (issuer == nil) != (issuerKey == nil) {
		return fmt.Errorf("%w: issuer certificate and key must be supplied together", ErrInvalidCertificateOptions)
	}
	if options.IsCA && issuer != nil {
		return fmt.Errorf("%w: certificate authorities must be self-signed", ErrInvalidCertificateOptions)
	}
	if options.IsCA && (len(options.DNSNames) != 0 || len(options.IPAddresses) != 0 || len(options.ExtKeyUsages) != 0) {
		return fmt.Errorf("%w: certificate authorities cannot carry leaf SANs or extended key usages", ErrInvalidCertificateOptions)
	}
	return nil
}

func certificateTemplate(
	options *CertificateOptions,
	subjectPublic any,
	serial *big.Int,
	now time.Time,
) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               options.Subject,
		NotBefore:             now.Add(-certificateClockSkew),
		NotAfter:              now.Add(options.ValidFor),
		BasicConstraintsValid: true,
		IsCA:                  options.IsCA,
		DNSNames:              options.DNSNames,
		IPAddresses:           options.IPAddresses,
		ExtKeyUsage:           options.ExtKeyUsages,
	}
	if options.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = 0
		template.MaxPathLenZero = true
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		if _, ok := subjectPublic.(*rsa.PublicKey); ok {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
	}
	return template
}

func certificateParentAndSigner(
	template *x509.Certificate,
	subjectSigner crypto.Signer,
	issuer *x509.Certificate,
	issuerKey *Key,
	now time.Time,
) (*x509.Certificate, crypto.Signer, error) {
	if issuer == nil {
		return template, subjectSigner, nil
	}
	if template.NotBefore.Before(issuer.NotBefore) {
		template.NotBefore = issuer.NotBefore
	}
	issuerSigner, err := validateCertificateIssuer(issuer, issuerKey, template, now)
	if err != nil {
		return nil, nil, err
	}
	return issuer, issuerSigner, nil
}

// CreateCertificateRequest creates a signed PKCS #10 certificate request.
func CreateCertificateRequest(options *CertificateRequestOptions, key *Key) ([]byte, error) {
	if options == nil {
		return nil, fmt.Errorf("%w: options are nil", ErrInvalidCertificateOptions)
	}
	if options.Subject.CommonName == "" {
		return nil, fmt.Errorf("%w: subject common name is empty", ErrInvalidCertificateOptions)
	}
	signer, err := key.Signer()
	if err != nil {
		return nil, fmt.Errorf("access CSR private key: %w", err)
	}
	template := &x509.CertificateRequest{
		Subject:     options.Subject,
		DNSNames:    options.DNSNames,
		IPAddresses: options.IPAddresses,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("create PKCS #10 certificate request: %w", err)
	}
	return der, nil
}

func validateCertificateIssuer(
	issuer *x509.Certificate,
	issuerKey *Key,
	template *x509.Certificate,
	now time.Time,
) (crypto.Signer, error) {
	invalidKeyUsage := issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0
	if !issuer.IsCA || !issuer.BasicConstraintsValid || invalidKeyUsage {
		return nil, ErrIssuerNotCA
	}
	if now.Before(issuer.NotBefore) || now.After(issuer.NotAfter) {
		return nil, fmt.Errorf(
			"%w: issuer is valid from %s through %s",
			ErrIssuerValidity,
			issuer.NotBefore.UTC().Format(time.RFC3339),
			issuer.NotAfter.UTC().Format(time.RFC3339),
		)
	}
	if template.NotAfter.After(issuer.NotAfter) {
		return nil, fmt.Errorf(
			"%w: requested leaf expiration %s is after issuer expiration %s; use a shorter leaf validity",
			ErrIssuerValidity,
			template.NotAfter.UTC().Format(time.RFC3339),
			issuer.NotAfter.UTC().Format(time.RFC3339),
		)
	}
	issuerSigner, err := issuerKey.Signer()
	if err != nil {
		return nil, fmt.Errorf("access issuer private key: %w", err)
	}
	keyPublicDER, err := x509.MarshalPKIXPublicKey(issuerSigner.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal issuer private key public part: %w", err)
	}
	certPublicDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal issuer certificate public key: %w", err)
	}
	if !bytes.Equal(keyPublicDER, certPublicDER) {
		return nil, ErrIssuerKeyMismatch
	}
	return issuerSigner, nil
}

func randomSerialNumber(random io.Reader) (*big.Int, error) {
	for {
		serial, err := rand.Int(random, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("generate certificate serial number: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}
