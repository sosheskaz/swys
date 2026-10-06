package netconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

const tcpRefusedRetryInterval = 25 * time.Millisecond

var (
	errNonTCPConnection = errors.New("TCP dialer returned a non-TCP connection")
	errNonUDPConnection = errors.New("UDP dialer returned a non-UDP connection")
)

// DialTCP establishes a TCP connection using the supplied setup context.
func DialTCP(ctx context.Context, address string) (*net.TCPConn, error) {
	return dialTCP(ctx, address, false)
}

// DialTCPRetryRefused retries refused connections within the supplied setup context.
func DialTCPRetryRefused(ctx context.Context, address string) (*net.TCPConn, error) {
	return dialTCP(ctx, address, true)
}

func dialTCP(ctx context.Context, address string, retryRefused bool) (*net.TCPConn, error) {
	var lastRefusal error
	for {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err == nil {
			tcpConnection, ok := connection.(*net.TCPConn)
			if !ok {
				return nil, errors.Join(errNonTCPConnection, connection.Close())
			}
			return tcpConnection, nil
		}
		if !retryRefused || !isConnectionRefused(err) {
			err = withContextCause(ctx, err)
			if lastRefusal != nil {
				err = errors.Join(lastRefusal, err)
			}
			return nil, fmt.Errorf("dial TCP endpoint %q: %w", address, err)
		}
		lastRefusal = err
		timer := time.NewTimer(tcpRefusedRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf(
				"dial TCP endpoint %q: %w",
				address,
				errors.Join(lastRefusal, cancellationError(ctx)),
			)
		case <-timer.C:
		}
	}
}

func withContextCause(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return errors.Join(err, cancellationError(ctx))
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline && !time.Now().Before(deadline) &&
		(errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)) {

		<-ctx.Done()
		return errors.Join(err, cancellationError(ctx))
	}
	return err
}

// DialUDP associates a UDP socket with one remote endpoint using the supplied
// setup context.
func DialUDP(ctx context.Context, address string) (*net.UDPConn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("dial UDP endpoint %q: %w", address, err)
	}
	udpConnection, ok := connection.(*net.UDPConn)
	if !ok {
		return nil, errors.Join(errNonUDPConnection, connection.Close())
	}
	return udpConnection, nil
}

// DialTLS establishes TCP, completes a TLS handshake, and returns the configured connection.
func DialTLS(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return dialTLS(ctx, address, config, false)
}

// DialTLSRetryRefused retries refused TCP connections before performing one TLS handshake.
func DialTLSRetryRefused(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return dialTLS(ctx, address, config, true)
}

func dialTLS(ctx context.Context, address string, config *tls.Config, retryRefused bool) (*tls.Conn, error) {
	tcpConnection, err := dialTCP(ctx, address, retryRefused)
	if err != nil {
		return nil, err
	}
	tlsConnection := tls.Client(tcpConnection, config)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("handshake with TLS endpoint %q: %w", address, err), tlsConnection.Close())
	}
	return tlsConnection, nil
}
