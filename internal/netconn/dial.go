package netconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const tcpRefusedRetryInterval = 25 * time.Millisecond

var (
	errNonTCPConnection = errors.New("TCP dialer returned a non-TCP connection")
	errNonUDPConnection = errors.New("UDP dialer returned a non-UDP connection")
)

// Dialer connects to requested endpoints, optionally overriding their
// addresses. The zero Dialer uses the system resolver. Overrides change only the
// addresses dialed; errors and TLS server names keep the requested endpoint.
type Dialer struct {
	Resolver Resolver
	// control fails chosen socket attempts in tests before they connect.
	control func(context.Context, string, string, syscall.RawConn) error
}

// DialTCP establishes a TCP connection using the supplied setup context.
func DialTCP(ctx context.Context, address string) (*net.TCPConn, error) {
	return Dialer{}.DialTCP(ctx, address)
}

// DialTCPRetryRefused retries refused connections within the supplied setup context.
func DialTCPRetryRefused(ctx context.Context, address string) (*net.TCPConn, error) {
	return Dialer{}.DialTCPRetryRefused(ctx, address)
}

// DialUDP associates a UDP socket with one remote endpoint using the supplied
// setup context.
func DialUDP(ctx context.Context, address string) (*net.UDPConn, error) {
	return Dialer{}.DialUDP(ctx, address)
}

// DialTLS establishes TCP, completes a TLS handshake, and returns the configured connection.
func DialTLS(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return Dialer{}.DialTLS(ctx, address, config)
}

// DialTLSRetryRefused retries refused TCP connections before performing one TLS handshake.
func DialTLSRetryRefused(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return Dialer{}.DialTLSRetryRefused(ctx, address, config)
}

// DialTCP establishes a TCP connection using the supplied setup context.
func (dialer Dialer) DialTCP(ctx context.Context, address string) (*net.TCPConn, error) {
	return dialer.dialTCP(ctx, address, false)
}

// DialTCPRetryRefused retries refused connections within the supplied setup
// context. With an address override, a round is retried only when every
// override address refused the connection.
func (dialer Dialer) DialTCPRetryRefused(ctx context.Context, address string) (*net.TCPConn, error) {
	return dialer.dialTCP(ctx, address, true)
}

// DialUDP associates a UDP socket with one remote endpoint using the supplied
// setup context.
func (dialer Dialer) DialUDP(ctx context.Context, address string) (*net.UDPConn, error) {
	connection, err := dialer.dial(ctx, "udp", address)
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
func (dialer Dialer) DialTLS(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return dialer.dialTLS(ctx, address, config, false)
}

// DialTLSRetryRefused retries refused TCP connections before performing one TLS handshake.
func (dialer Dialer) DialTLSRetryRefused(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	return dialer.dialTLS(ctx, address, config, true)
}

func (dialer Dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	// The caller's setup context already bounds every override attempt.
	return dialer.Resolver.DialContext(&net.Dialer{ControlContext: dialer.control}, 0)(ctx, network, address)
}

func (dialer Dialer) dialTCP(ctx context.Context, address string, retryRefused bool) (*net.TCPConn, error) {
	var lastRefusal error
	for {
		connection, err := dialer.dial(ctx, "tcp", address)
		if err == nil {
			tcpConnection, ok := connection.(*net.TCPConn)
			if !ok {
				return nil, errors.Join(errNonTCPConnection, connection.Close())
			}
			return tcpConnection, nil
		}
		if !retryRefused || !refusedEverywhere(err) {
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

// refusedEverywhere reports whether a dial failed only because each attempted
// address refused it; an override's joined error may also hold other failures.
func refusedEverywhere(err error) bool {
	var resolved *resolvedDialError
	if !errors.As(err, &resolved) {
		return isConnectionRefused(err)
	}
	for _, attempt := range resolved.attempts {
		if !isConnectionRefused(attempt) {
			return false
		}
	}
	return len(resolved.attempts) > 0
}

func (dialer Dialer) dialTLS(ctx context.Context, address string, config *tls.Config, retryRefused bool) (*tls.Conn, error) {
	tcpConnection, err := dialer.dialTCP(ctx, address, retryRefused)
	if err != nil {
		return nil, err
	}
	tlsConnection := tls.Client(tcpConnection, config)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("handshake with TLS endpoint %q: %w", address, err), tlsConnection.Close())
	}
	return tlsConnection, nil
}
