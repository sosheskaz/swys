package net_test

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExampleNetListenUDPDatagramExchange(t *testing.T) {
	t.Parallel()
	run := startExampleListenCommand(
		t,
		strings.NewReader("hello from listener"),
		"net", "listen", "-u", "0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err)
	connection, err := net.DialUDP("udp", nil, peer)
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close UDP example client: %v", closeErr)
		}
	})
	require.NoError(t, connection.SetDeadline(time.Now().Add(time.Second)))
	if _, err := connection.Write([]byte("hello from client")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	read, err := connection.Read(response)
	require.NoError(t, err)
	if got := string(response[:read]); got != "hello from listener" {
		t.Fatalf("client received %q, want listener datagram", got)
	}

	require.NoError(t, <-run.done)
	if got := run.stdout.String(); got != "hello from client" {
		t.Fatalf("listener output = %q, want client datagram", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "received udp ") {
		t.Fatalf("stderr = %q, want received endpoint summary", stderr)
	}
}
