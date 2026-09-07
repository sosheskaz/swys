package cmd

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExampleNetListenUDPDatagramExchange(t *testing.T) {
	run := startExampleListenCommand(
		t,
		strings.NewReader("hello from listener"),
		"net", "listen", "udp", "0",
		"--verbose",
	)
	address := readExampleListeningAddress(t, run.stderr, "listening udp ")
	remainingStderr := drainExampleStderr(run.stderr)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close UDP example client: %v", closeErr)
		}
	})
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("hello from client")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	read, err := connection.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(response[:read]); got != "hello from listener" {
		t.Fatalf("client received %q, want listener datagram", got)
	}

	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	if got := run.stdout.String(); got != "hello from client" {
		t.Fatalf("listener output = %q, want client datagram", got)
	}
	if stderr := <-remainingStderr; !strings.Contains(stderr, "received udp ") {
		t.Fatalf("stderr = %q, want received endpoint summary", stderr)
	}
}
