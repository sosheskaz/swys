package connectrpc

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http/httptrace"
	"sync"
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
			stream := &waitingStream{ctx: ctx, cancel: cancel, wait: duration, kind: spec.StreamType}
			// A failed Send can return before Connect closes the stream wrapper.
			stream.stopOnCancel = context.AfterFunc(ctx, stream.stopTimer)
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				WroteRequest: func(info httptrace.WroteRequestInfo) {
					if info.Err == nil {
						stream.startTimer()
					}
				},
			})
			delegate, err := next(ctx, spec)
			if err != nil {
				stream.stopOnCancel()
				stream.stopTimer()
				cancel(nil)
				return nil, err
			}
			stream.ClientStream = delegate
			return stream, nil
		}
	}
}

type waitingStream struct {
	connect.ClientStream
	ctx          context.Context //nolint:containedctx // Stream methods have no context argument; retain the cancellation cause.
	cancel       context.CancelCauseFunc
	stopOnCancel func() bool
	timer        *time.Timer
	wait         time.Duration
	mu           sync.Mutex
	kind         connect.StreamType
	finished     bool
}

// Single-request Send waits for response headers; CloseSend is too late to start --wait.
func (stream *waitingStream) startTimer() {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.finished || stream.timer != nil || stream.wait <= 0 {
		return
	}
	stream.timer = time.AfterFunc(stream.wait, func() {
		stream.cancel(fmt.Errorf("response drain timed out after %s: %w", stream.wait, context.DeadlineExceeded))
	})
}

func (stream *waitingStream) stopTimer() {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.finished = true
	if stream.timer != nil {
		stream.timer.Stop()
	}
}

// Send delegates while preserving the response deadline's cause.
func (stream *waitingStream) Send(message any) error {
	return stream.withDeadlineCause(stream.ClientStream.Send(message))
}

// Receive preserves completed protocol status even if output later exceeds a deadline.
func (stream *waitingStream) Receive(message any) error {
	err := stream.ClientStream.Receive(message)
	if errors.Is(err, io.EOF) || err == nil && stream.kind&connect.StreamTypeServer == 0 {
		stream.stopTimer()
	}
	return stream.withDeadlineCause(err)
}

func (stream *waitingStream) withDeadlineCause(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	if cause := context.Cause(stream.ctx); errors.Is(cause, context.DeadlineExceeded) {
		return connect.NewError(connect.CodeDeadlineExceeded, cause.Error()).WithCause(cause)
	}
	return err
}

// Close releases the timer after the sending goroutine has finished.
func (stream *waitingStream) Close() error {
	stream.stopOnCancel()
	stream.stopTimer()
	defer stream.cancel(nil)
	return closeStream(stream.ClientStream)
}
