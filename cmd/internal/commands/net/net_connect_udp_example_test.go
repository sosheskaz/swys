package net_test

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleNetConnectUDPDatagramExchange(t *testing.T) {
	t.Parallel()
	address, result := startExampleUDPServer(t, []byte("hello from server"))

	stdout, stderr, err := executeRootStreamsWithInput(
		t,
		strings.NewReader("hello from client"),
		"net", "connect", "--udp", address,
		"--verbose",
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Equal(t, "hello from server", stdout)
	assert.Contains(t, stderr, "connected udp ")
	if got := <-result; got.err != nil || got.request != "hello from client" {
		t.Fatalf("server result = %+v, want client datagram", got)
	}
}

func TestExampleNetConnectUDPRawDNSPacket(t *testing.T) {
	t.Parallel()
	const queryHex = "1a2b01000001000000000000076578616d706c6503636f6d0000010001"
	const responseHex = "1a2b81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c0004c0000201"
	query, err := hex.DecodeString(queryHex)
	require.NoError(t, err)
	response, err := hex.DecodeString(responseHex)
	require.NoError(t, err)
	address, result := startExampleUDPServer(t, response)

	stdout, _, err := executeRootStreamsWithInput(
		t,
		strings.NewReader(queryHex+"\n"),
		"net", "connect", "--udp", address,
		"--input-encoding", "hex",
		"--encoding", "hex",
		"--wait", "1s",
	)
	require.NoError(t, err)
	if stdout != responseHex {
		t.Fatalf("DNS response = %q, want %q", stdout, responseHex)
	}
	if got := <-result; got.err != nil || !strings.EqualFold(hex.EncodeToString([]byte(got.request)), hex.EncodeToString(query)) {
		t.Fatalf("server result = %+v, want raw DNS query %x", got, query)
	}
}

type exampleUDPResult struct {
	err     error
	request string
}

func startExampleUDPServer(t *testing.T, response []byte) (string, <-chan exampleUDPResult) {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close UDP example listener: %v", closeErr)
		}
	})
	result := make(chan exampleUDPResult, 1)
	go func() {
		if deadlineErr := listener.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
			result <- exampleUDPResult{err: deadlineErr}
			return
		}
		buffer := make([]byte, 65535)
		read, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			result <- exampleUDPResult{err: readErr}
			return
		}
		_, writeErr := listener.WriteToUDP(response, peer)
		result <- exampleUDPResult{request: string(buffer[:read]), err: writeErr}
	}()
	return listener.LocalAddr().String(), result
}
