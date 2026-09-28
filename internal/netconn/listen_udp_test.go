package netconn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenUDPReceivesAndRespondsOnLoopback(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	require.NoError(t, SendUDP(t.Context(), client, []byte("request")))
	request, peer, err := ReceiveUDPFrom(t.Context(), listener)
	require.NoError(t, err)
	require.Equal(t, "request", string(request))
	require.NoError(t, SendUDPTo(t.Context(), listener, []byte("response"), peer))
	response, err := ReceiveUDP(t.Context(), client)
	require.NoError(t, err)
	assert.Equal(t, "response", string(response))
}

func TestListenUDPRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	listener, err := ListenUDP(ctx, "127.0.0.1:0")
	require.ErrorIs(t, err, context.Canceled)
	if listener != nil {
		closeTestUDPConnection(t, listener)
		t.Fatal("ListenUDP returned a socket for a canceled context")
	}
}

func TestReceiveUDPFromCancellationClearsDeadline(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, _, err = ReceiveUDPFrom(ctx, listener)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	require.NoError(t, SendUDP(t.Context(), client, []byte("after timeout")))
	payload, _, err := ReceiveUDPFrom(t.Context(), listener)
	require.NoError(t, err)
	assert.Equal(t, "after timeout", string(payload), "socket reuse after timeout")
}

func TestListenUDPBindFailure(t *testing.T) {
	t.Parallel()

	first, err := ListenUDP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, first) })
	second, err := ListenUDP(t.Context(), first.LocalAddr().String())
	if err == nil {
		closeTestUDPConnection(t, second)
		t.Fatal("second UDP bind unexpectedly succeeded")
	}
}

func TestSendUDPToTransmitsZeroLengthDatagram(t *testing.T) {
	t.Parallel()

	listener, err := ListenUDP(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, listener) })
	client, err := DialUDP(t.Context(), listener.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { closeTestUDPConnection(t, client) })
	require.NoError(t, SendUDP(t.Context(), client, []byte("request")))
	_, peer, err := ReceiveUDPFrom(t.Context(), listener)
	require.NoError(t, err)
	require.NoError(t, SendUDPTo(t.Context(), listener, nil, peer))
	response, err := ReceiveUDP(t.Context(), client)
	require.NoError(t, err)
	assert.Empty(t, response, "zero-length response")
}

func TestSendUDPToRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	err := SendUDPTo(
		t.Context(),
		&net.UDPConn{},
		make([]byte, MaxUDPPayloadSize+1),
		&net.UDPAddr{},
	)
	require.ErrorIs(t, err, ErrDatagramTooLarge)
}
