// Package tlsconfig loads trust roots and matching certificate/key identities from CLI flags.
package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/internal/asym"
)

// Shared flag names keep TLS configuration consistent across command families.
const (
	CAEncodingFlagName   = "ca-encoding"
	CertEncodingFlagName = "cert-encoding"
	KeyEncodingFlagName  = "key-encoding"
	CertFlagName         = "cert"
	KeyFlagName          = "key"
	CAFlagName           = "ca"
	ServerNameFlagName   = "servername"
	SystemCAFlagName     = "system-ca"
)

// ErrClientKeyMismatch identifies a client certificate whose public key differs from --key.
var ErrClientKeyMismatch = errors.New("TLS client certificate and private key do not match")

// AddRootCAs replaces config.RootCAs only when --ca supplies a custom bundle.
func AddRootCAs(cmd *cobra.Command, config *tls.Config) error {
	roots, configured, err := CAPoolFromCommand(cmd)
	if err != nil {
		return err
	}
	if configured {
		config.RootCAs = roots
	}
	return nil
}

// CAPoolFromCommand loads --ca, optionally adding system roots for --system-ca.
// The boolean is false when --ca is absent, leaving the caller's trust policy intact.
func CAPoolFromCommand(cmd *cobra.Command) (*x509.CertPool, bool, error) {
	caPath, err := cmd.Flags().GetString(CAFlagName)
	if err != nil {
		return nil, false, fmt.Errorf("read ca flag: %w", err)
	}
	if caPath == "" {
		return nil, false, nil
	}
	systemCA, err := cmd.Flags().GetBool(SystemCAFlagName)
	if err != nil {
		return nil, false, fmt.Errorf("read system-ca flag: %w", err)
	}
	roots := x509.NewCertPool()
	if systemCA {
		systemRoots, poolErr := x509.SystemCertPool()
		if poolErr != nil {
			return nil, false, fmt.Errorf("load system certificate pool: %w", poolErr)
		}
		roots = systemRoots.Clone()
	}
	data, err := readCommandArtifact(cmd, CAFlagName, caPath, artifact.MaxCertificateBytes)
	if err != nil {
		return nil, false, err
	}
	certificates, err := certinput.ParsePEMCertificates(data)
	if err != nil {
		return nil, false, fmt.Errorf("parse --ca: %w", err)
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	return roots, true, nil
}

// ClientIdentityFromCommand loads --cert and --key using ErrClientKeyMismatch for mismatches.
func ClientIdentityFromCommand(cmd *cobra.Command) (tls.Certificate, bool, error) {
	return IdentityFromCommand(cmd, ErrClientKeyMismatch)
}

// IdentityFromCommand loads a certificate chain and matching private signing key.
// The boolean is false when --cert is absent; mismatches return mismatchError.
func IdentityFromCommand(cmd *cobra.Command, mismatchError error) (tls.Certificate, bool, error) {
	certPath, err := cmd.Flags().GetString(CertFlagName)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read cert flag: %w", err)
	}
	if certPath == "" {
		return tls.Certificate{}, false, nil
	}
	keyPath, err := cmd.Flags().GetString(KeyFlagName)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read key flag: %w", err)
	}
	certData, err := readCommandArtifact(cmd, CertFlagName, certPath, artifact.MaxCertificateBytes)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	certificates, err := certinput.ParsePEMCertificates(certData)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse --cert: %w", err)
	}
	keyData, err := readCommandArtifact(cmd, KeyFlagName, keyPath, artifact.MaxKeyBytes)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	key, err := asym.ParseKey(keyData)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse --key: %w", err)
	}
	signer, err := key.Signer()
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("validate --key private signing material: %w", err)
	}
	if err := validateIdentityMatch(certificates[0], signer.Public(), mismatchError); err != nil {
		return tls.Certificate{}, false, err
	}
	chain := make([][]byte, len(certificates))
	for i, certificate := range certificates {
		chain[i] = certificate.Raw
	}
	return tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: certificates[0]}, true, nil
}

func validateIdentityMatch(certificate *x509.Certificate, publicKey any, mismatchError error) error {
	certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal --cert public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal --key public part: %w", err)
	}
	if !bytes.Equal(certificateDER, keyDER) {
		return mismatchError
	}
	return nil
}

// ReadArtifact bounds a selected file and adds its flag name and path to read errors.
func ReadArtifact(flagName, path string, limit int64) ([]byte, error) {
	data, err := artifact.ReadFile(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", flagName, path, err)
	}
	return data, nil
}
