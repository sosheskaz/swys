package connectrpc

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"time"

	"connectrpc.com/connect/v2"
)

var errStreamFinished = errors.New("RPC finished receiving")

// NextMessage must interrupt any blocked input read when ctx is canceled.
type NextMessage func(ctx context.Context) (jsontext.Value, error)

// Stream sends messages and emits responses as they arrive. The final server
// status ends the RPC even when the local input is still open.
func (client *Client) Stream(parent context.Context, kind connect.StreamType, next NextMessage, emit func(jsontext.Value) error) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	spec := connect.Spec{Procedure: client.endpoint.Procedure, StreamType: kind}
	if kind == connect.StreamTypeServer {
		request, err := next(ctx)
		if err != nil {
			return fmt.Errorf("read Connect request: %w", err)
		}
		stream, err := client.client.CallServerStream(ctx, spec, &request)
		if err != nil {
			return fmt.Errorf("open Connect stream: %w", err)
		}
		return errors.Join(receiveMessages(stream, emit), closeStream(stream))
	}
	stream, err := client.client.CallClientStream(ctx, spec)
	if err != nil {
		return fmt.Errorf("open Connect stream: %w", err)
	}
	if err := stream.SendHeaders(); err != nil {
		return errors.Join(fmt.Errorf("send Connect headers: %w", err), closeStream(stream))
	}
	sent := make(chan error, 1)
	go func() { sent <- sendMessages(ctx, cancel, stream, next) }()
	receiveErr := receiveMessages(stream, emit)
	cancel(errStreamFinished)
	sendErr := <-sent
	if sendErr != nil && !errors.Is(sendErr, errStreamFinished) && errors.Is(context.Cause(ctx), sendErr) {
		return errors.Join(sendErr, closeStream(stream))
	}
	return errors.Join(receiveErr, closeStream(stream))
}

func sendMessages(ctx context.Context, cancel context.CancelCauseFunc, stream connect.ClientStream, next NextMessage) error {
	for {
		message, err := next(ctx)
		if errors.Is(err, io.EOF) {
			if err := stream.CloseSend(); err != nil {
				return fmt.Errorf("finish Connect input: %w", err)
			}
			return nil
		}
		if err != nil {
			failure := fmt.Errorf("read Connect input: %w", err)
			cancel(failure)
			return failure
		}
		if err := stream.Send(&message); err != nil {
			return fmt.Errorf("send Connect message: %w", err)
		}
	}
}

func receiveMessages(stream connect.ClientStream, emit func(jsontext.Value) error) error {
	for {
		var response jsontext.Value
		if err := stream.Receive(&response); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receive Connect response: %w", err)
		}
		if err := emit(response); err != nil {
			return fmt.Errorf("write Connect response: %w", err)
		}
	}
}

func closeStream(stream connect.ClientStream) error {
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close Connect stream: %w", err)
	}
	return nil
}

func responseWait(duration time.Duration) connect.ClientInterceptor {
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(parent context.Context, spec connect.Spec) (connect.ClientStream, error) {
			ctx, cancel := context.WithCancelCause(parent)
			stream, err := next(ctx, spec)
			if err != nil {
				cancel(nil)
				return nil, err
			}
			return &waitingStream{ClientStream: stream, ctx: ctx, cancel: cancel, wait: duration}, nil
		}
	}
}

type waitingStream struct {
	connect.ClientStream
	ctx    context.Context //nolint:containedctx // Receive has no context argument; keep the stream's cancellation cause
	cancel context.CancelCauseFunc
	timer  *time.Timer
	wait   time.Duration
}

// CloseSend starts the drain budget only after request sending completes.
func (stream *waitingStream) CloseSend() error {
	if err := stream.ClientStream.CloseSend(); err != nil {
		return fmt.Errorf("close Connect send side: %w", err)
	}
	if stream.wait > 0 {
		stream.timer = time.AfterFunc(stream.wait, func() {
			stream.cancel(fmt.Errorf("response drain timed out after %s: %w", stream.wait, context.DeadlineExceeded))
		})
	}
	return nil
}

// Receive retains the deadline identity when a drain timer cancels the transport.
func (stream *waitingStream) Receive(message any) error {
	err := stream.ClientStream.Receive(message)
	if err != nil {
		if cause := context.Cause(stream.ctx); cause != nil && errors.Is(cause, context.DeadlineExceeded) {
			return connect.NewError(connect.CodeDeadlineExceeded, cause.Error()).WithCause(cause)
		}
		return fmt.Errorf("receive Connect stream: %w", err)
	}
	return nil
}

// Close is called after the sending goroutine has finished, releasing its timer.
func (stream *waitingStream) Close() error {
	if stream.timer != nil {
		stream.timer.Stop()
	}
	defer stream.cancel(nil)
	return closeStream(stream.ClientStream)
}
