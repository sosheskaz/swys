package netconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errUnexpectedRequest = errors.New("unexpected request")
	errTestInput         = errors.New("input failed")
	errTestOutput        = errors.New("output failed")
	errTestCloseWrite    = errors.New("close write failed")
	errTestClose         = errors.New("close failed")
	errTestRelayCanceled = errors.New("relay canceled")
	errTestRelayWrapped  = errors.Join(errTestRelayCanceled, context.Canceled)
)

func TestRelayHalfClosesAndDrainsPeerResponse(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	serverErr := make(chan error, 1)
	go func() {
		request, err := io.ReadAll(peer)
		if err != nil {
			serverErr <- err
			return
		}
		if string(request) != "request" {
			serverErr <- errUnexpectedRequest
			return
		}
		if _, err := io.WriteString(peer, "response"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- peer.Close()
	}()

	var output bytes.Buffer
	if err := RelayWithOptions(
		t.Context(),
		client,
		strings.NewReader("request"),
		&output,
		RelayOptions{Wait: time.Second, CloseWrite: true},
	); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, <-serverErr)
	assert.Equal(t, "response", output.String())
}

func TestRelayDuplexContinuesSendingAfterPeerEOF(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	observed := newObservedStream(client)
	input, inputWriter := io.Pipe()
	serverRequest := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		closeWriteErr := peer.CloseWrite()
		request, readErr := io.ReadAll(peer)
		serverRequest <- string(request)
		serverErr <- errors.Join(closeWriteErr, readErr)
	}()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RelayWithOptions(
			t.Context(),
			observed,
			input,
			io.Discard,
			RelayOptions{Wait: time.Second, Duplex: true},
		)
	}()

	waitForSignal(t, observed.peerEOF, "client receive EOF")
	if _, err := io.WriteString(inputWriter, "complete request"); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, inputWriter.Close())
	require.NoError(t, <-relayDone)
	require.NoError(t, <-serverErr)
	assert.Equal(t, "complete request", <-serverRequest)
}

func TestRelayReturnsSendFailureAfterPeerEOF(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	observed := newObservedStream(client)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- errors.Join(peer.CloseWrite(), drainConnection(peer))
	}()

	releaseInput := make(chan struct{})
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RelayWithOptions(
			t.Context(),
			observed,
			&gatedErrorReader{ready: releaseInput, err: errTestInput},
			io.Discard,
			RelayOptions{Wait: time.Second, Duplex: true},
		)
	}()

	waitForSignal(t, observed.peerEOF, "client receive EOF")
	select {
	case err := <-relayDone:
		close(releaseInput)
		t.Fatalf("relay returned before the send failure: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseInput)
	require.ErrorIs(t, <-relayDone, errTestInput)
	require.NoError(t, <-serverDone)
	if observedCloseCount := observed.closeCount(); observedCloseCount != 1 {
		t.Fatalf("connection close count = %d, want 1", observedCloseCount)
	}
}

func TestRelayReturnsReceiveFailureWithoutWaitingForInput(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	input, inputWriter := io.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(peer, "response")
		serverDone <- writeErr
	}()

	err := RelayWithOptions(
		t.Context(), client, input, failingWriter{err: errTestOutput}, RelayOptions{Wait: time.Second},
	)
	if closeErr := inputWriter.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	require.ErrorIs(t, err, errTestOutput)
	require.NoError(t, <-serverDone)
}

func TestRelayCancellationAfterPeerEOFDoesNotWaitForBlockedSend(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	observed := newObservedStream(client)
	input, inputWriter := io.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- errors.Join(peer.CloseWrite(), drainConnection(peer))
	}()

	ctx, cancel := context.WithCancel(t.Context())
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RelayWithOptions(
			ctx, observed, input, io.Discard, RelayOptions{Wait: time.Second, Duplex: true},
		)
	}()
	waitForSignal(t, observed.peerEOF, "client receive EOF")
	cancel()
	require.ErrorIs(t, <-relayDone, context.Canceled)
	require.NoError(t, inputWriter.Close())
	require.NoError(t, <-serverDone)
}

func TestFinishPeerFirstPrefersCompletedSendErrorOverCancellation(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	sent := make(chan copyResult, 1)
	sent <- copyResult{direction: sendInputData, err: errTestInput}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := finishPeerFirst(ctx, client, sent, copyResult{direction: receivePeerData})
	require.ErrorIs(t, err, errTestInput)
	if errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, do not discard completed send for cancellation", err)
	}
}

func TestFinishPeerImmediatelyReturnsQueuedSendError(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	observed := newObservedStream(client)
	sent := make(chan copyResult, 1)
	sent <- copyResult{direction: sendInputData, err: errTestInput}

	err := finishPeerImmediately(observed, sent, copyResult{direction: receivePeerData})
	require.ErrorIs(t, err, errTestInput)
	assert.Equal(t, 1, observed.closeCount(), "connection close count")
}

func TestFinishPeerImmediatelyReturnsSendErrorQueuedWhileClosing(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	sent := make(chan copyResult, 1)
	connection := &callbackCloseStream{
		StreamConn: client,
		beforeClose: func() {
			sent <- copyResult{direction: sendInputData, err: errTestInput}
		},
	}

	err := finishPeerImmediately(connection, sent, copyResult{direction: receivePeerData})
	require.ErrorIs(t, err, errTestInput)
}

func TestFinishPeerImmediatelyIgnoresExpectedSendErrorsQueuedWhileClosing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		name string
	}{
		{name: "network closed", err: net.ErrClosed},
		{name: "pipe closed", err: io.ErrClosedPipe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client, _ := newTCPStreamPair(t)
			sent := make(chan copyResult, 1)
			connection := &callbackCloseStream{
				StreamConn: client,
				beforeClose: func() {
					sent <- copyResult{direction: sendInputData, err: test.err}
				},
			}

			if err := finishPeerImmediately(connection, sent, copyResult{direction: receivePeerData}); err != nil {
				t.Fatalf("error = %v, want local shutdown error suppressed", err)
			}
		})
	}
}

func TestFinishPeerImmediatelyDoesNotWaitForSend(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	observed := newObservedStream(client)
	finished := make(chan error, 1)
	go func() {
		finished <- finishPeerImmediately(
			observed,
			make(chan copyResult),
			copyResult{direction: receivePeerData},
		)
	}()
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("peer EOF waited for an unfinished send")
	}
	assert.Equal(t, 1, observed.closeCount(), "connection close count")
}

func TestRelayDrainExpiryReturnsTimeoutAndPreservesPrefix(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	observed := newObservedStream(client)
	prefixWritten := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(peer, "partial response")
		close(prefixWritten)
		serverDone <- errors.Join(writeErr, drainConnection(peer))
	}()

	var output bytes.Buffer
	const wait = 50 * time.Millisecond
	err := RelayWithOptions(
		t.Context(),
		observed,
		&gatedEOFReader{ready: prefixWritten},
		&output,
		RelayOptions{Wait: wait},
	)
	require.ErrorIs(t, err, ErrDrainTimeout)
	if !strings.Contains(err.Error(), wait.String()) {
		t.Fatalf("error = %q, want elapsed wait %s", err, wait)
	}
	require.Equal(t, "partial response", output.String(), "preserved prefix")
	waitForSignal(t, observed.closed, "connection close")
	require.NoError(t, <-serverDone)
}

func TestExpireDrainRechecksCompletedReceive(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	received := make(chan copyResult, 1)
	received <- copyResult{direction: receivePeerData}
	err := expireDrain(client, received, time.Second)
	if errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("error = %v, want completed receive without timeout", err)
	}
}

func TestExpireDrainJoinsIndependentCloseAndReceiveErrors(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	received := make(chan copyResult, 1)
	connection := &callbackCloseStream{
		StreamConn: client,
		err:        errTestClose,
		beforeClose: func() {
			received <- copyResult{direction: receivePeerData, err: errTestOutput}
		},
	}
	err := expireDrain(connection, received, time.Second)
	for _, want := range []error{ErrDrainTimeout, errTestClose, errTestOutput} {
		require.ErrorIs(t, err, want)
	}
}

func TestRelayZeroWaitDrainsUntilPeerEOF(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	serverErr := make(chan error, 1)
	go func() {
		request, readErr := io.ReadAll(peer)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if len(request) != 0 {
			serverErr <- fmt.Errorf("%w: got %q, want empty", errUnexpectedRequest, request)
			return
		}
		time.Sleep(30 * time.Millisecond)
		_, writeErr := io.WriteString(peer, "late response")
		serverErr <- errors.Join(writeErr, peer.Close())
	}()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := RelayWithOptions(
		ctx, client, strings.NewReader(""), &output, RelayOptions{CloseWrite: true},
	); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, <-serverErr)
	assert.Equal(t, "late response", output.String())
}

func TestRelayCancellationWaitsForReceiveCopy(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	observed := newObservedStream(client)
	writer := newBlockingWriter()
	serverDone := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(peer, "response")
		serverDone <- errors.Join(writeErr, drainConnection(peer))
	}()

	ctx, cancel := context.WithCancel(t.Context())
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RelayWithOptions(ctx, observed, strings.NewReader(""), writer, RelayOptions{})
	}()
	waitForSignal(t, writer.started, "receive output write")
	cancel()
	waitForSignal(t, observed.closed, "connection close")
	select {
	case err := <-relayDone:
		writer.releaseWrite()
		t.Fatalf("relay returned while receive output was still writing: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	writer.releaseWrite()
	require.ErrorIs(t, <-relayDone, context.Canceled)
	waitForSignal(t, writer.stopped, "receive output stop")
	require.NoError(t, <-serverDone)
}

func TestRelayCancellationClosesConnection(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		connection := newCancelBlockingStream()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()

		err := RelayWithOptions(ctx, connection, strings.NewReader(""), io.Discard, RelayOptions{})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		select {
		case <-connection.closed:
		default:
			t.Fatal("relay cancellation did not close the connection")
		}
	})
}

func TestCancellationErrorIncludesCanonicalContextErrorOnce(t *testing.T) {
	t.Parallel()
	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := cancellationError(ctx)
		if got := strings.Count(err.Error(), context.Canceled.Error()); got != 1 {
			t.Fatalf("canonical cancellation occurrences = %d in %q, want 1", got, err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithDeadline(t.Context(), time.Time{})
		defer cancel()

		err := cancellationError(ctx)
		if got := strings.Count(err.Error(), context.DeadlineExceeded.Error()); got != 1 {
			t.Fatalf("canonical deadline occurrences = %d in %q, want 1", got, err)
		}
	})
}

func TestRelayPreservesCancellationCause(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		connection := newCancelBlockingStream()
		ctx, cancel := context.WithCancelCause(t.Context())
		relayDone := make(chan error, 1)
		go func() {
			relayDone <- RelayWithOptions(ctx, connection, strings.NewReader(""), io.Discard, RelayOptions{})
		}()
		synctest.Wait()
		cancel(errTestRelayCanceled)

		require.ErrorIs(t, <-relayDone, errTestRelayCanceled)
	})
}

func TestRelayPreservesWrappedCancellationCause(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		connection := newCancelBlockingStream()
		ctx, cancel := context.WithCancelCause(t.Context())
		relayDone := make(chan error, 1)
		go func() {
			relayDone <- RelayWithOptions(ctx, connection, strings.NewReader(""), io.Discard, RelayOptions{})
		}()
		synctest.Wait()
		cancel(errTestRelayWrapped)

		require.ErrorIs(t, <-relayDone, errTestRelayWrapped)
	})
}

func TestRelayAlreadyCanceledDoesNotWaitForBlockedInput(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	t.Cleanup(func() { closeTestConnection(t, "peer connection", peer) })
	input, inputWriter := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := RelayWithOptions(ctx, client, input, io.Discard, RelayOptions{Wait: time.Second})
	if closeErr := inputWriter.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	require.ErrorIs(t, err, context.Canceled)
}

func TestRelayReturnsCloseWriteFailure(t *testing.T) {
	t.Parallel()

	client, peer := newTCPStreamPair(t)
	serverDone := make(chan error, 1)
	go func() { serverDone <- drainConnection(peer) }()

	connection := &failingCloseWriteStream{StreamConn: client, err: errTestCloseWrite}
	err := RelayWithOptions(
		t.Context(),
		connection,
		strings.NewReader(""),
		io.Discard,
		RelayOptions{Wait: time.Second, CloseWrite: true},
	)
	require.ErrorIs(t, err, errTestCloseWrite)
	require.NoError(t, <-serverDone)
}

func TestRelayRejectsNegativeWait(t *testing.T) {
	t.Parallel()

	client, _ := newTCPStreamPair(t)
	err := RelayWithOptions(
		t.Context(), client, strings.NewReader(""), io.Discard, RelayOptions{Wait: -time.Second},
	)
	require.ErrorIs(t, err, ErrInvalidWait)
}

func TestRelayClosesConnectionWhenInputFails(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(peer)
		peerDone <- errors.Join(err, peer.Close())
	}()

	err := RelayWithOptions(
		t.Context(), client, iotest.ErrReader(errTestInput), io.Discard, RelayOptions{Wait: time.Second},
	)
	require.ErrorIs(t, err, errTestInput)
	require.NoError(t, <-peerDone)
}

func TestRelayReturnsOutputFailure(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		<-client.writeClosed
		_, err := io.WriteString(peer, "response")
		peerDone <- errors.Join(err, peer.Close())
	}()

	err := RelayWithOptions(
		t.Context(),
		client,
		strings.NewReader(""),
		failingWriter{err: errTestOutput},
		RelayOptions{Wait: time.Second, CloseWrite: true},
	)
	require.ErrorIs(t, err, errTestOutput)
	require.NoError(t, <-peerDone)
}

func TestRelayReceiveOnlyPreservesCancellationCause(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		connection := newCancelBlockingStream()
		ctx, cancel := context.WithCancelCause(t.Context())
		relayDone := make(chan error, 1)
		go func() {
			relayDone <- RelayWithOptions(
				ctx,
				connection,
				iotest.ErrReader(errTestInput),
				io.Discard,
				RelayOptions{ReceiveOnly: true},
			)
		}()
		synctest.Wait()
		cancel(errTestRelayWrapped)

		require.ErrorIs(t, <-relayDone, errTestRelayWrapped)
		select {
		case <-connection.closed:
		default:
			t.Fatal("receive-only cancellation did not close the connection")
		}
	})
}

func TestRelayReceiveOnlyReturnsOutputFailureWithoutReadingInput(t *testing.T) {
	t.Parallel()

	client, peer := newPipeStream(t)
	peerDone := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(peer, "response")
		peerDone <- errors.Join(writeErr, peer.Close())
	}()

	err := RelayWithOptions(
		t.Context(),
		client,
		iotest.ErrReader(errTestInput),
		failingWriter{err: errTestOutput},
		RelayOptions{ReceiveOnly: true},
	)
	require.ErrorIs(t, err, errTestOutput)
	if errors.Is(err, errTestInput) {
		t.Fatalf("error = %v, receive-only relay read input", err)
	}
	require.NoError(t, <-peerDone)
}

type pipeStream struct {
	net.Conn
	writeClosed chan struct{}
	closeOnce   sync.Once
}

type observedStream struct {
	StreamConn
	peerEOF   chan struct{}
	closed    chan struct{}
	eofOnce   sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	closes    int
}

type failingCloseWriteStream struct {
	StreamConn
	err error
}

type callbackCloseStream struct {
	StreamConn
	beforeClose func()
	err         error
}

type gatedEOFReader struct {
	ready <-chan struct{}
}

type gatedErrorReader struct {
	ready <-chan struct{}
	err   error
}

type blockingWriter struct {
	started chan struct{}
	stopped chan struct{}
	release chan struct{}
	start   sync.Once
	stop    sync.Once
}

type failingWriter struct {
	err error
}

type cancelBlockingStream struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newCancelBlockingStream() *cancelBlockingStream {
	return &cancelBlockingStream{closed: make(chan struct{})}
}

func (connection *cancelBlockingStream) Read([]byte) (int, error) {
	<-connection.closed
	return 0, net.ErrClosed
}

func (*cancelBlockingStream) Write(buffer []byte) (int, error) {
	return len(buffer), nil
}

func (connection *cancelBlockingStream) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*cancelBlockingStream) CloseWrite() error {
	return nil
}

func (*cancelBlockingStream) LocalAddr() net.Addr {
	return testNetAddr("local")
}

func (*cancelBlockingStream) RemoteAddr() net.Addr {
	return testNetAddr("remote")
}

func (*cancelBlockingStream) SetDeadline(time.Time) error {
	return nil
}

func (*cancelBlockingStream) SetReadDeadline(time.Time) error {
	return nil
}

func (*cancelBlockingStream) SetWriteDeadline(time.Time) error {
	return nil
}

type testNetAddr string

func (testNetAddr) Network() string {
	return "test"
}

func (address testNetAddr) String() string {
	return string(address)
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func newPipeStream(tb testing.TB) (*pipeStream, net.Conn) {
	tb.Helper()
	client, peer := net.Pipe()
	return &pipeStream{Conn: client, writeClosed: make(chan struct{})}, peer
}

func (connection *pipeStream) CloseWrite() error {
	connection.closeOnce.Do(func() { close(connection.writeClosed) })
	return nil
}

func newTCPStreamPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	accepted := make(chan struct {
		connection *net.TCPConn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		accepted <- struct {
			connection *net.TCPConn
			err        error
		}{connection: connection, err: acceptErr}
	}()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		closeTestConnection(t, "TCP listener", listener)
		t.Fatalf("listener address has type %T, want *net.TCPAddr", listener.Addr())
	}
	client, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		closeTestConnection(t, "TCP listener", listener)
		t.Fatal(err)
	}
	result := <-accepted
	if err := listener.Close(); err != nil {
		closeTestConnection(t, "client connection", client)
		t.Fatal(err)
	}
	if result.err != nil {
		closeTestConnection(t, "client connection", client)
		t.Fatal(result.err)
	}
	t.Cleanup(func() {
		closeTestConnection(t, "client connection", client)
		closeTestConnection(t, "peer connection", result.connection)
	})
	return client, result.connection
}

func newObservedStream(connection StreamConn) *observedStream {
	return &observedStream{
		StreamConn: connection,
		peerEOF:    make(chan struct{}),
		closed:     make(chan struct{}),
	}
}

func (connection *observedStream) Read(buffer []byte) (int, error) {
	read, err := connection.StreamConn.Read(buffer)
	if errors.Is(err, io.EOF) {
		connection.eofOnce.Do(func() { close(connection.peerEOF) })
	}
	return read, err //nolint:wrapcheck // preserve net.Conn error identity in the relay fixture
}

func (connection *observedStream) Close() error {
	connection.mu.Lock()
	connection.closes++
	connection.mu.Unlock()
	connection.closeOnce.Do(func() { close(connection.closed) })
	return connection.StreamConn.Close() //nolint:wrapcheck // preserve net.Conn error identity in the relay fixture
}

func (connection *observedStream) closeCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.closes
}

func (connection *failingCloseWriteStream) CloseWrite() error {
	return connection.err
}

func (connection *callbackCloseStream) Close() error {
	connection.beforeClose()
	return errors.Join(connection.StreamConn.Close(), connection.err)
}

func (reader *gatedEOFReader) Read([]byte) (int, error) {
	<-reader.ready
	return 0, io.EOF
}

func (reader *gatedErrorReader) Read([]byte) (int, error) {
	<-reader.ready
	return 0, reader.err
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (writer *blockingWriter) Write(buffer []byte) (int, error) {
	writer.start.Do(func() { close(writer.started) })
	<-writer.release
	writer.stop.Do(func() { close(writer.stopped) })
	return len(buffer), nil
}

func (writer *blockingWriter) releaseWrite() {
	select {
	case <-writer.release:
	default:
		close(writer.release)
	}
}

func drainConnection(connection net.Conn) error {
	_, err := io.Copy(io.Discard, connection)
	if err != nil {
		return fmt.Errorf("drain connection: %w", err)
	}
	return nil
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func closeTestConnection(tb testing.TB, description string, connection io.Closer) {
	tb.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		tb.Errorf("close %s: %v", description, err)
	}
}
