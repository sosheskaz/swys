package crpc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestCRPCBidiReceivesBeforeInputEOF(t *testing.T) {
	t.Parallel()
	server := streamingServer(t, "bidi", false)
	input, send := io.Pipe()
	t.Cleanup(func() { assert.NoError(t, input.Close()); assert.NoError(t, send.Close()) })
	output := &messageOutput{messages: make(chan string, 1)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	root := cmd.NewCommand()
	root.SetContext(ctx)
	finished := make(chan error, 1)
	go func() {
		finished <- testcmd.Run(t, root, input, output, io.Discard, "crpc", server.URL+echoMethod, "--stream", "bidi")
	}()
	_, err := io.WriteString(send, "{\"text\":\"first\"}\n")
	require.NoError(t, err)
	select {
	case message := <-output.messages:
		assert.JSONEq(t, `{"text":"first"}`, message)
	case <-ctx.Done():
		t.Fatal("response did not arrive while request input remained open")
	}
	require.NoError(t, send.Close())
	require.NoError(t, <-finished)
}

func TestCRPCEarlyCompletionCancelsBorrowedInput(t *testing.T) {
	t.Parallel()
	input := &blockedInput{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(input.release) })
	server := streamHandlerServer(t, connect.StreamTypeBidi, func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
		select {
		case <-input.started:
		case <-ctx.Done():
			return ctx.Err()
		}
		return stream.Send(&structpb.Struct{})
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	root := cmd.NewCommand()
	root.SetContext(ctx)
	output, _, err := testcmd.RunStreams(t, root, input, "crpc", server.URL+echoMethod, "--stream", "bidi")
	require.NoError(t, err)
	assert.JSONEq(t, "{}", string(output))
	assert.False(t, input.closed.Load(), "cancellation must not close borrowed stdin")
}

func TestCRPCStreamKeepsMessagesOnFinalFailure(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"remote status", "wait deadline", "broken output"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			server := streamHandlerServer(t, connect.StreamTypeServer, func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
				var request structpb.Struct
				if err := stream.Receive(&request); err != nil {
					return fmt.Errorf("receive fixture request: %w", err)
				}
				if err := stream.Send(&request); err != nil {
					return fmt.Errorf("send fixture response: %w", err)
				}
				if failure == "remote status" {
					return connect.NewError(connect.CodeUnavailable, "fixture unavailable")
				}
				<-ctx.Done()
				return ctx.Err()
			})
			args := []string{"crpc", server.URL + echoMethod, "--stream", "server", "-d", `{"received":true}`, "--timeout", "5s"}
			if failure == "wait deadline" {
				args = append(args, "--wait", "20ms")
			}
			if failure == "broken output" {
				root := cmd.NewCommand()
				root.SetContext(t.Context())
				err := testcmd.Run(t, root, strings.NewReader(""), failingOutput{}, io.Discard, args...)
				require.ErrorIs(t, err, errBrokenOutput)
				return
			}
			output, _, err := run(t, nil, args...)
			require.Error(t, err)
			assert.JSONEq(t, `{"received":true}`, output)
			if failure == "wait deadline" {
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			} else {
				assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
			}
		})
	}
}

func TestCRPCClientStreamSendsNoInventedEmptyMessage(t *testing.T) {
	t.Parallel()
	server := streamingServer(t, "client", false)
	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--stream", "client", "--stdin", "never")
	require.NoError(t, err)
	assert.JSONEq(t, `{"count":0}`, output)
}

func TestCRPCStreamRequiresTerminalStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, _ *http.Request) {
		output.Header().Set("Content-Type", "application/connect+json")
		// A complete JSON envelope without the required end-of-stream envelope.
		_, err := output.Write([]byte{0, 0, 0, 0, 2, '{', '}'})
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	output, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--stream", "server", "-d", "{}")
	require.Error(t, err)
	assert.JSONEq(t, "{}", output)
}

func TestCRPCStreamingTimeoutIncludesInputPauses(t *testing.T) {
	t.Parallel()
	server := streamingServer(t, "bidi", false)
	input := &blockedInput{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(input.release) })
	_, _, err := run(t, input, "crpc", server.URL+echoMethod, "--stream", "bidi", "--timeout", "20ms")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, input.closed.Load())
}

func TestCRPCStreamingOverTLSHTTP2(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"server", "client", "bidi"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			server := streamingServer(t, mode, true)
			output, diagnostics, err := run(t, nil, "crpc", server.URL+echoMethod, "--stream", mode, "--insecure", "-d", `{}`, "-v")
			require.NoError(t, err)
			assert.NotEmpty(t, output)
			assert.Contains(t, diagnostics, "Connect transport: HTTP/2.0")
		})
	}
}

func TestCRPCBidiExplainsHTTP2Requirement(t *testing.T) {
	t.Parallel()
	server := echoServer(t, false, false)
	_, _, err := run(t, nil, "crpc", server.URL+echoMethod, "--stream", "bidi", "-d", "{}", "--timeout", "1s")
	require.ErrorContains(t, err, "HTTP/2 required")
}

func streamHandlerServer(t *testing.T, kind connect.StreamType, handler connect.ServerFunc) *httptest.Server {
	t.Helper()
	service := connect.NewServer()
	service.Register(connect.Method{Spec: connect.Spec{Procedure: echoMethod, StreamType: kind}, Handler: handler})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service)
	server := httptest.NewUnstartedServer(mux)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	return server
}

type messageOutput struct{ messages chan string }

func (output *messageOutput) Write(data []byte) (int, error) {
	output.messages <- string(data)
	return len(data), nil
}

type blockedInput struct {
	started, release chan struct{}
	once             sync.Once
	closed           atomic.Bool
}

func (input *blockedInput) Read([]byte) (int, error) {
	input.once.Do(func() { close(input.started) })
	<-input.release
	return 0, io.EOF
}
func (input *blockedInput) Close() error { input.closed.Store(true); return nil }

var errBrokenOutput = errors.New("fixture output failed")

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errBrokenOutput }
