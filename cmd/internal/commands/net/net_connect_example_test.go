package net_test

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleNetConnectTCPDefaultsToHalfCloseAndDrain(t *testing.T) {
	t.Parallel()
	requestPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(requestPath, []byte("request"), 0o600))
	address, serverResult := startEOFResponseServer(t, "request", "response")
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)

	stdout, stderr, err := executeRootCommandStreams(
		t,
		root,
		"net", "connect", address,
		"--input", requestPath,
	)
	require.NoError(t, err, "default TCP pipe exchange: %v", err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.request != "request" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestExampleNetConnectTCPHTTPResponse(t *testing.T) {
	t.Parallel()
	const request = "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
	requestPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(requestPath, []byte(request), 0o600))
	address, serverResult := startWriteOpenResponseServer(t, request, response)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", address,
		"--input", requestPath,
		"--close-write=false",
		"--wait", "1s",
	)
	require.NoError(t, err)
	if stdout != response {
		t.Fatalf("response = %q, want %q", stdout, response)
	}
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.request != request {
		t.Fatalf("server result = %+v", result)
	}
}

func TestExampleNetConnectTCPCanCloseWriteAfterInput(t *testing.T) {
	t.Parallel()
	requestPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(requestPath, []byte("request"), 0o600))
	address, serverResult := startEOFResponseServer(t, "request", "response")

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", address,
		"--input", requestPath,
		"--close-write",
		"--wait", "1s",
	)
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.request != "request" {
		t.Fatalf("server result = %+v", result)
	}
}

var (
	errExampleUnexpectedRequest = errors.New("unexpected example request")
	errUnexpectedHalfClose      = errors.New("client closed its write side before the response")
	errUnexpectedExtraData      = errors.New("client sent data after the request")
)

type exampleExchangeResult struct {
	err     error
	request string
}

func startWriteOpenResponseServer(
	t *testing.T,
	wantRequest string,
	response string,
) (string, <-chan exampleExchangeResult) {
	t.Helper()
	listener := listenExampleTCP(t)
	result := make(chan exampleExchangeResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- exampleExchangeResult{err: acceptErr}
			return
		}
		serverResult := exampleExchangeResult{}
		defer func() {
			serverResult.err = errors.Join(serverResult.err, connection.Close())
			result <- serverResult
		}()

		request := make([]byte, len(wantRequest))
		if _, err := io.ReadFull(connection, request); err != nil {
			serverResult.err = err
			return
		}
		serverResult.request = string(request)
		if serverResult.request != wantRequest {
			serverResult.err = fmt.Errorf("%w: got %q, want %q", errExampleUnexpectedRequest, request, wantRequest)
			return
		}
		if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			serverResult.err = err
			return
		}
		buffer := make([]byte, 1)
		_, readErr := connection.Read(buffer)
		if errors.Is(readErr, io.EOF) {
			serverResult.err = errUnexpectedHalfClose
			return
		}
		if readErr == nil {
			serverResult.err = errUnexpectedExtraData
			return
		}
		var networkErr net.Error
		if !errors.As(readErr, &networkErr) || !networkErr.Timeout() {
			serverResult.err = fmt.Errorf("wait for open write side: %w", readErr)
			return
		}
		if err := connection.SetReadDeadline(time.Time{}); err != nil {
			serverResult.err = err
			return
		}
		_, serverResult.err = io.WriteString(connection, response)
	}()
	return listener.Addr().String(), result
}

func startEOFResponseServer(
	t *testing.T,
	wantRequest string,
	response string,
) (string, <-chan exampleExchangeResult) {
	t.Helper()
	listener := listenExampleTCP(t)
	result := make(chan exampleExchangeResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- exampleExchangeResult{err: acceptErr}
			return
		}
		serverResult := exampleExchangeResult{}
		defer func() {
			serverResult.err = errors.Join(serverResult.err, connection.Close())
			result <- serverResult
		}()

		request, readErr := io.ReadAll(connection)
		serverResult.request = string(request)
		if readErr != nil {
			serverResult.err = readErr
			return
		}
		if serverResult.request != wantRequest {
			serverResult.err = fmt.Errorf("%w: got %q, want %q", errExampleUnexpectedRequest, request, wantRequest)
			return
		}
		_, serverResult.err = io.WriteString(connection, response)
	}()
	return listener.Addr().String(), result
}

func listenExampleTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close example TCP listener: %v", closeErr)
		}
	})
	return listener
}

func TestExampleNetConnectIndependentlyEncodedTLSArtifacts(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	ca, err := os.ReadFile(identity.caCert)
	require.NoError(t, err)
	cert, err := os.ReadFile(identity.clientCert)
	require.NoError(t, err)
	key, err := os.ReadFile(identity.clientKey)
	require.NoError(t, err)
	directory := t.TempDir()
	certPath, keyPath, payloadPath := filepath.Join(directory, "cert"), filepath.Join(directory, "key"), filepath.Join(directory, "payload")
	require.NoError(t, os.WriteFile(certPath, []byte(base64.StdEncoding.EncodeToString(cert)), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(base32.StdEncoding.EncodeToString(key)), 0o600))
	require.NoError(t, os.WriteFile(payloadPath, []byte(base64.StdEncoding.EncodeToString([]byte("request"))), 0o600))
	var serverResult <-chan exchangeResult
	received := false
	t.Cleanup(func() {
		if received || serverResult == nil {
			return
		}
		select {
		case <-serverResult:
		case <-time.After(7 * time.Second):
			t.Error("TLS fixture worker did not exit")
		}
	})
	address, result := startTLSExchangeServer(t, &identity, true, nil)
	serverResult = result
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := newRootCmd()
	command.SetContext(ctx)
	command.SetIn(strings.NewReader(hex.EncodeToString(ca)))
	stdout, stderr, err := executeRootCommandStreams(t, command,
		"net", "connect", "--tls", address, "--servername", "localhost",
		"--ca", "-", "--ca-encoding", "hex", "--cert", certPath, "--cert-encoding", "base64",
		"--key", keyPath, "--key-encoding", "base32", "--input", payloadPath, "--input-encoding", "base64")
	require.NoError(t, err)
	assert.Equal(t, "response", stdout)
	assert.Empty(t, stderr)
	select {
	case got := <-serverResult:
		received = true
		require.NoError(t, got.err)
		assert.Equal(t, "request", got.request)
		assert.True(t, got.clientVerified, "server verified the independently decoded client identity")
	case <-ctx.Done():
		t.Fatal("TLS fixture did not report the exchange")
	}
}
