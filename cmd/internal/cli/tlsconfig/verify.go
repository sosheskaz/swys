package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrNoPeerCertificates identifies a handshake that presented no server certificate.
var ErrNoPeerCertificates = errors.New("TLS peer presented no certificates")

// VerifyPeer repeats crypto/tls client verification for a completed handshake so
// diagnostics can report the result an --insecure* flag tolerated. As with
// tls.Config.RootCAs, nil roots select the system pool. serverName must be the
// verification name, not ConnectionState.ServerName, which omits IP addresses.
func VerifyPeer(state *tls.ConnectionState, roots *x509.CertPool, serverName string) ([][]*x509.Certificate, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, ErrNoPeerCertificates
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: roots, DNSName: serverName, Intermediates: intermediates,
	})
	if err != nil {
		return nil, fmt.Errorf("verify TLS peer: %w", err)
	}
	return chains, nil
}

// VerifiedChains returns a completed handshake's verified chains. When config
// tolerated a failure, it repeats verification so diagnostics can report the
// outcome and its reason. dialedHost names the target when config.ServerName is empty.
func VerifiedChains(state *tls.ConnectionState, config *tls.Config, dialedHost string) ([][]*x509.Certificate, error) {
	if len(state.VerifiedChains) > 0 || config == nil || !config.InsecureSkipVerify {
		return state.VerifiedChains, nil
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = dialedHost
	}
	return VerifyPeer(state, config.RootCAs, serverName)
}
