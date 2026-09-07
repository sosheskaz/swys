package netconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// MaxUDPPayloadSize is the largest UDP payload portable across IPv4 and IPv6
	// without IPv6 jumbograms.
	MaxUDPPayloadSize  = 65507
	maxUDPDatagramSize = 65535
)

var (
	// ErrDatagramTooLarge indicates that one decoded input payload cannot fit in
	// the portable UDP payload limit.
	ErrDatagramTooLarge = errors.New("UDP datagram exceeds maximum payload size")
	// ErrUDPResponseTimeout indicates that a connector received no response
	// before its configured wait elapsed.
	ErrUDPResponseTimeout = errors.New("UDP response wait timed out")
)

// ReadDatagram buffers exactly one decoded input payload with a portable UDP
// size bound.
func ReadDatagram(input io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(input, MaxUDPPayloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("read UDP datagram input: %w", err)
	}
	if len(payload) > MaxUDPPayloadSize {
		return nil, fmt.Errorf("%w: got more than %d bytes", ErrDatagramTooLarge, MaxUDPPayloadSize)
	}
	return payload, nil
}

type datagramRead struct {
	err     error
	payload []byte
}

// ReadDatagramContext buffers one decoded input payload while allowing the
// caller to stop waiting without closing a caller-owned reader.
func ReadDatagramContext(ctx context.Context, input io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read UDP datagram input: %w", err)
	}

	result := make(chan datagramRead, 1)
	// An arbitrary io.Reader cannot be interrupted safely. Isolate the blocking
	// read so cancellation can release network resources without closing stdin.
	go func() {
		payload, err := ReadDatagram(input)
		result <- datagramRead{err: err, payload: payload}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("read UDP datagram input: %w", ctx.Err())
	case read := <-result:
		return read.payload, read.err
	}
}

// SendUDP sends exactly one datagram on a connected UDP socket.
func SendUDP(ctx context.Context, connection *net.UDPConn, payload []byte) error {
	if len(payload) > MaxUDPPayloadSize {
		return fmt.Errorf("%w: got %d bytes, maximum is %d", ErrDatagramTooLarge, len(payload), MaxUDPPayloadSize)
	}
	remote := connection.RemoteAddr()
	written, err := udpOperation(ctx, connection, func() (int, error) {
		return connection.Write(payload)
	})
	if err != nil {
		return fmt.Errorf("send UDP datagram to %q: %w", remote, err)
	}
	if written != len(payload) {
		return fmt.Errorf("send UDP datagram to %q: wrote %d of %d bytes: %w", remote, written, len(payload), io.ErrShortWrite)
	}
	return nil
}

// ReceiveUDP receives exactly one datagram from a connected UDP socket.
func ReceiveUDP(ctx context.Context, connection *net.UDPConn) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("receive UDP datagram: %w", err)
	}
	buffer := make([]byte, maxUDPDatagramSize)
	read, err := udpOperation(ctx, connection, func() (int, error) {
		return connection.Read(buffer)
	})
	if err != nil {
		return nil, fmt.Errorf("receive UDP datagram from %q: %w", connection.RemoteAddr(), err)
	}
	return buffer[:read], nil
}

// ReceiveUDPFrom receives exactly one datagram and its source from an
// unconnected UDP socket.
func ReceiveUDPFrom(ctx context.Context, connection *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("receive UDP datagram: %w", err)
	}
	buffer := make([]byte, maxUDPDatagramSize)
	var peer *net.UDPAddr
	read, err := udpOperation(ctx, connection, func() (int, error) {
		var readErr error
		var read int
		read, peer, readErr = connection.ReadFromUDP(buffer)
		if readErr != nil {
			return read, fmt.Errorf("read UDP datagram: %w", readErr)
		}
		return read, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("receive UDP datagram on %q: %w", connection.LocalAddr(), err)
	}
	return buffer[:read], peer, nil
}

// SendUDPTo sends exactly one datagram to a selected peer from an unconnected
// UDP socket.
func SendUDPTo(ctx context.Context, connection *net.UDPConn, payload []byte, peer *net.UDPAddr) error {
	if len(payload) > MaxUDPPayloadSize {
		return fmt.Errorf("%w: got %d bytes, maximum is %d", ErrDatagramTooLarge, len(payload), MaxUDPPayloadSize)
	}
	written, err := udpOperation(ctx, connection, func() (int, error) {
		return connection.WriteToUDP(payload, peer)
	})
	if err != nil {
		return fmt.Errorf("send UDP datagram to %q: %w", peer, err)
	}
	if written != len(payload) {
		return fmt.Errorf("send UDP datagram to %q: wrote %d of %d bytes: %w", peer, written, len(payload), io.ErrShortWrite)
	}
	return nil
}

func udpOperation(
	ctx context.Context,
	connection *net.UDPConn,
	operation func() (int, error),
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("UDP operation canceled before I/O: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return 0, fmt.Errorf("set UDP operation deadline: %w", err)
		}
	}
	cancellationResult := make(chan error, 1)
	stopCancellation := context.AfterFunc(ctx, func() {
		cancellationResult <- connection.SetDeadline(time.Now())
	})

	processed, operationErr := operation()
	var cancellationErr error
	if !stopCancellation() {
		if err := <-cancellationResult; err != nil {
			cancellationErr = fmt.Errorf("interrupt canceled UDP operation: %w", err)
		}
	}
	clearErr := connection.SetDeadline(time.Time{})
	if operationErr != nil {
		contextErr := ctx.Err()
		var networkErr net.Error
		if contextErr == nil && errors.As(operationErr, &networkErr) && networkErr.Timeout() {
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				<-ctx.Done()
				contextErr = ctx.Err()
			}
		}
		if contextErr != nil {
			operationErr = contextErr
		}
	}
	if clearErr != nil {
		clearErr = fmt.Errorf("clear UDP operation deadline: %w", clearErr)
	}
	return processed, errors.Join(operationErr, cancellationErr, clearErr)
}
