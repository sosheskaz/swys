package connectrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupTimeoutEndsAtConnectionAcquisition(t *testing.T) {
	t.Parallel()
	for _, connected := range []bool{false, true} {
		name := "stalled setup"
		if connected {
			name = "acquired connection"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				endpoint, err := ParseEndpoint("https://example.test/pkg.Service/Method", "")
				require.NoError(t, err)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL.String(), http.NoBody)
				require.NoError(t, err)
				var observed context.Context
				transport := &requestTransport{endpoint: endpoint, setup: time.Second, base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					observed = request.Context()
					if connected {
						httptrace.ContextClientTrace(observed).GotConn(httptrace.GotConnInfo{})
						return &http.Response{Body: io.NopCloser(strings.NewReader("{}"))}, nil
					}
					<-observed.Done()
					return nil, observed.Err()
				})}
				if connected {
					response, err := transport.RoundTrip(request)
					require.NoError(t, err)
					synctest.Sleep(2 * time.Second)
					assert.NoError(t, observed.Err(), "setup timeout must not bound response reading")
					require.NoError(t, response.Body.Close())
					assert.ErrorIs(t, observed.Err(), context.Canceled)
					return
				}
				finished := make(chan error, 1)
				go func() {
					response, err := transport.RoundTrip(request)
					if response != nil {
						err = errors.Join(err, response.Body.Close())
					}
					finished <- err
				}()
				synctest.Sleep(time.Second - time.Nanosecond)
				assert.Empty(t, finished, "setup must not expire early")
				synctest.Sleep(time.Nanosecond)
				require.Len(t, finished, 1)
				require.ErrorIs(t, <-finished, context.DeadlineExceeded)
			})
		})
	}
}

func TestResponseWaitStartsAfterSendingAndDoesNotReset(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var callContext context.Context
		stream, err := responseWait(time.Second)(func(ctx context.Context, _ connect.Spec) (connect.ClientStream, error) {
			callContext = ctx
			return &waitingFixture{ctx: ctx}, nil
		})(t.Context(), connect.Spec{})
		require.NoError(t, err)
		defer func() { assert.NoError(t, stream.Close()) }()
		synctest.Sleep(2 * time.Second)
		assert.NoError(t, callContext.Err(), "input pauses do not spend --wait")
		require.NoError(t, stream.CloseSend())
		synctest.Sleep(time.Second / 2)
		require.NoError(t, stream.Receive(nil), "receiving a message does not reset the drain budget")
		finished := make(chan error, 1)
		go func() { finished <- stream.Receive(nil) }()
		synctest.Sleep(time.Second/2 - time.Nanosecond)
		assert.Empty(t, finished)
		synctest.Sleep(time.Nanosecond)
		require.Len(t, finished, 1)
		err = <-finished
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, connect.CodeDeadlineExceeded, connect.CodeOf(err))
	})
}

type waitingFixture struct {
	ctx           context.Context //nolint:containedctx // fixture implements context-free Receive
	firstReceived bool
}

func (*waitingFixture) SendHeaders() error { return nil }
func (*waitingFixture) Send(any) error     { return nil }
func (*waitingFixture) CloseSend() error   { return nil }
func (*waitingFixture) Close() error       { return nil }
func (fixture *waitingFixture) Receive(any) error {
	if !fixture.firstReceived {
		fixture.firstReceived = true
		return nil
	}
	<-fixture.ctx.Done()
	return fmt.Errorf("fixture receive: %w", fixture.ctx.Err())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
