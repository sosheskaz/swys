package cmd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExampleNetConnectTCPHTTPResponse(t *testing.T) {
	t.Parallel()
	const request = "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
	requestPath := filepath.Join(t.TempDir(), "request")
	if err := os.WriteFile(requestPath, []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}
	address, serverResult := startWriteOpenResponseServer(t, request, response)

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tcp", address,
		"--input", requestPath,
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != response {
		t.Fatalf("response = %q, want %q", stdout, response)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want quiet success", stderr)
	}
	if result := <-serverResult; result.err != nil || result.request != request {
		t.Fatalf("server result = %+v", result)
	}
}

func TestExampleNetConnectTCPCanCloseWriteAfterInput(t *testing.T) {
	t.Parallel()
	requestPath := filepath.Join(t.TempDir(), "request")
	if err := os.WriteFile(requestPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	address, serverResult := startEOFResponseServer(t, "request", "response")

	stdout, stderr, err := executeRootStreams(
		t,
		"net", "connect", "tcp", address,
		"--input", requestPath,
		"--close-write",
		"--wait", "1s",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "response" {
		t.Fatalf("response = %q, want response", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want quiet success", stderr)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close example TCP listener: %v", closeErr)
		}
	})
	return listener
}
