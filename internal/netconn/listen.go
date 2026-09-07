package netconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

var (
	errNonTCPListener = errors.New("TCP listen config returned a non-TCP listener")
	errNonUDPListener = errors.New("UDP listen config returned a non-UDP connection")
)

// ListenTCP binds a TCP listener using the supplied setup context.
func ListenTCP(ctx context.Context, address string) (*net.TCPListener, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listen on TCP endpoint %q: %w", address, err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on TCP endpoint %q: %w", address, err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, errors.Join(errNonTCPListener, listener.Close())
	}
	return tcpListener, nil
}

// ListenUDP binds a UDP socket using the supplied setup context.
func ListenUDP(ctx context.Context, address string) (*net.UDPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listen on UDP endpoint %q: %w", address, err)
	}
	connection, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on UDP endpoint %q: %w", address, err)
	}
	udpConnection, ok := connection.(*net.UDPConn)
	if !ok {
		return nil, errors.Join(errNonUDPListener, connection.Close())
	}
	return udpConnection, nil
}

type acceptTCPResult struct {
	connection *net.TCPConn
	err        error
}

// AcceptTCP accepts one connection and closes the listener before returning.
// Canceling the setup context closes the listener and any concurrently accepted
// connection.
func AcceptTCP(ctx context.Context, listener *net.TCPListener) (*net.TCPConn, error) {
	address := listener.Addr().String()
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("accept TCP connection on %q: %w", address, err),
			closeTCPListener(listener),
		)
	}

	accepted := make(chan acceptTCPResult, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		accepted <- acceptTCPResult{connection: connection, err: err}
	}()

	select {
	case result := <-accepted:
		closeErr := closeTCPListener(listener)
		if result.err != nil {
			return nil, errors.Join(
				fmt.Errorf("accept TCP connection on %q: %w", address, result.err),
				closeErr,
			)
		}
		if closeErr != nil {
			return nil, errors.Join(closeErr, closeTCPConnection(result.connection))
		}
		return result.connection, nil
	case <-ctx.Done():
		closeErr := closeTCPListener(listener)
		result := <-accepted
		var acceptErr error
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			acceptErr = fmt.Errorf("accept TCP connection on %q after cancellation: %w", address, result.err)
		}
		return nil, errors.Join(
			fmt.Errorf("accept TCP connection on %q: %w", address, ctx.Err()),
			closeErr,
			acceptErr,
			closeTCPConnection(result.connection),
		)
	}
}

// AcceptTLS accepts one TCP connection, closes the listener, and completes a
// server-side TLS handshake using the same setup context.
func AcceptTLS(ctx context.Context, listener *net.TCPListener, config *tls.Config) (*tls.Conn, error) {
	connection, err := AcceptTCP(ctx, listener)
	if err != nil {
		return nil, err
	}
	tlsConnection := tls.Server(connection, config)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		endpoints := fmt.Sprintf("%s <- %s", connection.LocalAddr(), connection.RemoteAddr())
		return nil, errors.Join(
			fmt.Errorf("handshake with accepted TLS connection %s: %w", endpoints, err),
			closeTLSConnection(tlsConnection),
		)
	}
	return tlsConnection, nil
}

func closeTCPListener(listener *net.TCPListener) error {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close TCP listener: %w", err)
	}
	return nil
}

func closeTCPConnection(connection *net.TCPConn) error {
	if connection == nil {
		return nil
	}
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close accepted TCP connection: %w", err)
	}
	return nil
}

func closeTLSConnection(connection *tls.Conn) error {
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close accepted TLS connection: %w", err)
	}
	return nil
}
