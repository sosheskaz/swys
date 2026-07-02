package asym

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

// CertFromDial fetches the peer-provided certificate chain from a TLS endpoint.
func CertFromDial(ctx context.Context, address string) ([]*x509.Certificate, string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "", fmt.Errorf("parse TLS address %q: %w", address, err)
	}

	dialer := &tls.Dialer{Config: &tls.Config{
		// Certificate verification is performed after the handshake so invalid
		// and expired certificates can still be inspected.
		InsecureSkipVerify: true,
	}}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", fmt.Errorf("dial TLS endpoint %q: %w", address, err)
	}
	defer connection.Close() //nolint:errcheck // certificate data is already in memory; a TLS close error is not actionable

	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return nil, "", errors.New("TLS dialer returned a non-TLS connection")
	}
	certs := tlsConnection.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, "", errors.New("TLS peer returned no certificates")
	}
	return certs, host, nil
}
