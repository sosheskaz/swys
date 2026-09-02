package netconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

var errNonTCPConnection = errors.New("TCP dialer returned a non-TCP connection")

// DialTCP establishes a TCP connection using the supplied setup context.
func DialTCP(ctx context.Context, address string) (*net.TCPConn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial TCP endpoint %q: %w", address, err)
	}
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		return nil, errors.Join(errNonTCPConnection, connection.Close())
	}
	return tcpConnection, nil
}

// DialTLS establishes TCP, completes a TLS handshake, and returns the configured connection.
func DialTLS(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	tcpConnection, err := DialTCP(ctx, address)
	if err != nil {
		return nil, err
	}
	tlsConnection := tls.Client(tcpConnection, config)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("handshake with TLS endpoint %q: %w", address, err), tlsConnection.Close())
	}
	return tlsConnection, nil
}
