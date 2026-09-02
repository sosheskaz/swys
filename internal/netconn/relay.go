package netconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	// ErrInvalidWait indicates a negative post-input drain duration.
	ErrInvalidWait = errors.New("invalid connection drain wait")
	// ErrDrainTimeout indicates that the response drain window elapsed.
	ErrDrainTimeout = errors.New("connection response drain timed out")
)

// StreamConn is a full-duplex network connection that supports write-side shutdown.
type StreamConn interface {
	net.Conn
	CloseWrite() error
}

type copyResult struct {
	err       error
	direction copyDirection
}

type copyDirection uint8

const (
	receivePeerData copyDirection = iota
	sendInputData
)

// Relay copies input to the peer and peer data to output until both directions
// finish, the drain period expires after input EOF, or the context is canceled.
func Relay(
	ctx context.Context,
	connection StreamConn,
	input io.Reader,
	output io.Writer,
	wait time.Duration,
	closeWrite bool,
) error {
	if wait < 0 {
		return fmt.Errorf("%w: %s", ErrInvalidWait, wait)
	}

	received := make(chan copyResult, 1)
	sent := make(chan copyResult, 1)
	go copyStream(received, receivePeerData, output, connection)
	go copyStream(sent, sendInputData, connection, input)

	select {
	case result := <-received:
		return finishPeerFirst(ctx, connection, sent, result)
	case result := <-sent:
		return finishInputFirst(ctx, connection, received, result, wait, closeWrite)
	case <-ctx.Done():
		return cancelRelay(connection, received, ctx.Err())
	}
}

func copyStream(result chan<- copyResult, direction copyDirection, output io.Writer, input io.Reader) {
	_, err := io.Copy(output, input)
	result <- copyResult{direction: direction, err: err}
}

func finishPeerFirst(
	ctx context.Context,
	connection StreamConn,
	sent <-chan copyResult,
	received copyResult,
) error {
	if received.err != nil {
		return errors.Join(wrapCopyError(received), wrapCloseError(connection.Close()))
	}

	select {
	case result := <-sent:
		return finishPeerAndSend(connection, result)
	default:
	}
	select {
	case result := <-sent:
		return finishPeerAndSend(connection, result)
	case <-ctx.Done():
		return errors.Join(ctx.Err(), wrapCloseError(connection.Close()))
	}
}

func finishPeerAndSend(connection StreamConn, sent copyResult) error {
	return errors.Join(wrapCopyError(sent), wrapCloseError(connection.Close()))
}

func finishInputFirst(
	ctx context.Context,
	connection StreamConn,
	received <-chan copyResult,
	sent copyResult,
	wait time.Duration,
	closeWrite bool,
) error {
	if sent.err != nil {
		return closeAfterFailure(connection, received, wrapCopyError(sent))
	}
	if closeWrite {
		if err := connection.CloseWrite(); err != nil {
			return closeAfterFailure(connection, received, fmt.Errorf("close connection write side: %w", err))
		}
	}
	if wait == 0 {
		select {
		case result := <-received:
			return finishReceived(connection, result)
		case <-ctx.Done():
			return cancelRelay(connection, received, ctx.Err())
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case result := <-received:
		return finishReceived(connection, result)
	case <-timer.C:
		return expireDrain(connection, received, wait)
	case <-ctx.Done():
		return cancelRelay(connection, received, ctx.Err())
	}
}

func finishReceived(connection StreamConn, received copyResult) error {
	return errors.Join(wrapCopyError(received), wrapCloseError(connection.Close()))
}

func expireDrain(connection StreamConn, received <-chan copyResult, wait time.Duration) error {
	select {
	case result := <-received:
		return finishReceived(connection, result)
	default:
	}

	timeoutErr := fmt.Errorf("%w after %s", ErrDrainTimeout, wait)
	closeErr := wrapCloseError(connection.Close())
	result := <-received
	return errors.Join(timeoutErr, closeErr, wrapExpectedCloseCopyError(result))
}

func cancelRelay(connection StreamConn, received <-chan copyResult, contextErr error) error {
	closeErr := wrapCloseError(connection.Close())
	result := <-received
	return errors.Join(contextErr, closeErr, wrapExpectedCloseCopyError(result))
}

func closeAfterFailure(connection StreamConn, received <-chan copyResult, cause error) error {
	closeErr := wrapCloseError(connection.Close())
	result := <-received
	return errors.Join(cause, closeErr, wrapExpectedCloseCopyError(result))
}

func wrapCopyError(result copyResult) error {
	if result.err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", result.direction, result.err)
}

func (direction copyDirection) String() string {
	if direction == receivePeerData {
		return "receive peer data"
	}
	return "send input data"
}

func wrapExpectedCloseCopyError(result copyResult) error {
	if isExpectedCloseError(result.err) {
		return nil
	}
	return wrapCopyError(result)
}

func wrapCloseError(err error) error {
	if err == nil || isExpectedCloseError(err) {
		return nil
	}
	return fmt.Errorf("close connection: %w", err)
}

func isExpectedCloseError(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
