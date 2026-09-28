package net

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/netconn"
)

func TestNetProtocolDependentDefaultsDoNotMutate(t *testing.T) {
	t.Parallel()
	connect := newNetConnectCmd(commandio.NewLifecycle())
	for _, test := range []struct {
		protocol string
		wait     time.Duration
	}{
		{protocol: netProtocolTCP},
		{protocol: netProtocolUDP, wait: 5 * time.Second},
		{protocol: netProtocolTLS},
		{protocol: netProtocolUDP, wait: 5 * time.Second},
		{protocol: netProtocolTCP},
	} {
		setNetTestProtocol(t, connect, test.protocol)
		wait, err := netConnectWait(connect)
		require.NoError(t, err)
		assert.Equal(t, test.wait, wait, "%s wait", test.protocol)
		timeout, err := connect.Flags().GetDuration("timeout")
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, timeout, "%s connector timeout", test.protocol)
	}

	explicitZero := newNetConnectTestCommand(t, netProtocolUDP)
	require.NoError(t, explicitZero.Flags().Set("wait", "0"))
	for _, protocol := range []string{netProtocolTCP, netProtocolUDP, netProtocolTLS} {
		setNetTestProtocol(t, explicitZero, protocol)
		wait, err := netConnectWait(explicitZero)
		require.NoError(t, err)
		assert.Zero(t, wait, "explicit zero wait for %s", protocol)
	}

	listen := newNetListenCmd(commandio.NewLifecycle())
	if timeout, err := listen.Flags().GetDuration("timeout"); err != nil || timeout != 0 {
		t.Fatalf("listener timeout = %s, error %v; want 0", timeout, err)
	}
}

func TestNetListenTCPDiagnosticWriteFailures(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close diagnostic listener: %v", err)
		}
	})
	want := errListenDiagnosticOutput
	require.ErrorIs(t, writeTCPListeningDetails(failingWriter{err: want}, listener), want)

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- connection
		acceptErr <- err
	}()
	client := dialListenTestTCP(t, listener.Addr().String())
	t.Cleanup(func() { closeListenTestTCP(t, client) })
	server := <-accepted
	require.NoError(t, <-acceptErr)
	t.Cleanup(func() { closeListenTestTCP(t, server) })
	require.ErrorIs(t, writeTCPAcceptedDetails(failingWriter{err: want}, server), want)
}

func TestValidateTLSServerIdentityAcceptsPresentedOrder(t *testing.T) {
	t.Parallel()
	certificates, privateKey := newListenTestIntermediateChain(t)
	identity := tls.Certificate{Certificate: certificates, PrivateKey: privateKey}
	require.NoError(t, validateTLSServerIdentity(&identity))
}

func TestRespondUDPDatagramReturnsOutputFailureBeforeSending(t *testing.T) {
	t.Parallel()
	want := errUDPTestOutput
	err := respondUDPDatagram(
		t.Context(),
		&net.UDPConn{},
		&net.UDPAddr{},
		[]byte("request"),
		strings.NewReader("response"),
		failingWriter{err: want},
	)
	require.ErrorIs(t, err, want)
}

func TestUDPListenerDiagnosticsReturnOutputFailures(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	require.ErrorIs(t, writeUDPListeningDetails(failingWriter{err: errUDPTestDiagnostic}, listener), errUDPTestDiagnostic)
	require.ErrorIs(t, writeUDPReceivedDetails(
		failingWriter{err: errUDPTestDiagnostic},
		listener.LocalAddr(),
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	), errUDPTestDiagnostic)
}

func TestExchangeUDPDatagramReturnsOutputFailure(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, peer, readErr := listener.ReadFromUDP(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := listener.WriteToUDP([]byte("response"), peer)
		serverDone <- writeErr
	}()
	connection, err := netconn.DialUDP(t.Context(), listener.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { closeUDPTest(t, connection) })
	want := errUDPTestOutput
	err = exchangeUDPDatagram(t.Context(), connection, strings.NewReader("request"), failingWriter{err: want}, time.Second)
	require.ErrorIs(t, err, want)
	require.NoError(t, <-serverDone)
}

func TestWriteUDPConnectionDetailsReturnsOutputFailure(t *testing.T) {
	t.Parallel()
	listener := listenUDPTest(t)
	connection, err := netconn.DialUDP(t.Context(), listener.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { closeUDPTest(t, connection) })
	want := errUDPTestDiagnostic
	require.ErrorIs(t, writeUDPConnectionDetails(failingWriter{err: want}, connection), want)
}

func TestNetStreamLifecycleFlags(t *testing.T) {
	t.Parallel()

	for _, command := range []*cobra.Command{
		newNetConnectTestCommand(t, "tcp"),
		newNetConnectTestCommand(t, "tls"),
		newNetListenTestCommand(t, "tcp"),
		newNetListenTestCommand(t, "tls"),
	} {
		require.NoError(t, command.Flags().Set("duplex", "false"))
		require.NoError(t, command.Flags().Set("close-write", "false"))
		options, err := networkStreamOptionsFromCommand(command)
		require.NoError(t, err)
		if options.duplex || options.closeWrite {
			t.Errorf(
				"%s lifecycle options = duplex:%t close-write:%t, want both false",
				command.CommandPath(),
				options.duplex,
				options.closeWrite,
			)
		}
	}
}

func TestNetConnectUDPFlagContract(t *testing.T) {
	t.Parallel()
	netConnectUDPCmd := newNetConnectTestCommand(t, "udp")
	options, err := networkDatagramConnectOptionsFromCommand(netConnectUDPCmd)
	require.NoError(t, err)
	if options.timeout != 5*time.Second || options.wait != 5*time.Second {
		t.Fatalf("UDP defaults = timeout:%s wait:%s, want 5s and 5s", options.timeout, options.wait)
	}
	require.NoError(t, netConnectUDPCmd.Flags().Set("wait", "0"))
	options, err = networkDatagramConnectOptionsFromCommand(netConnectUDPCmd)
	require.NoError(t, err)
	assert.Zero(t, options.wait, "explicit UDP wait")
	assert.NotNil(t, netConnectUDPCmd.Flags().Lookup("close-write"), "net connect union has no --close-write flag")
}

func newListenTestIntermediateChain(t *testing.T) ([][]byte, ed25519.PrivateKey) {
	t.Helper()
	now := time.Now()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ordered root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intermediatePublic, intermediateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ordered intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		root,
		intermediatePublic,
		rootKey,
	)
	require.NoError(t, err)
	intermediate, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	leafPublic, leafKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ordered leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		intermediate,
		leafPublic,
		intermediateKey,
	)
	require.NoError(t, err)
	return [][]byte{leafDER, intermediateDER, rootDER}, leafKey
}

func TestNetALPNCompletionParser(t *testing.T) {
	t.Parallel()
	parsed, err := parseALPN("custom-protocol")
	require.NoError(t, err)
	assert.Equal(t, []string{"custom-protocol"}, parsed)
	parsed, err = parseALPN("")
	require.NoError(t, err)
	assert.Nil(t, parsed)
}

func listenUDPTest(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { closeUDPTest(t, listener) })
	return listener
}

func closeUDPTest(t *testing.T, connection io.Closer) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close UDP test socket: %v", err)
	}
}

func dialListenTestTCP(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	require.NoError(t, err)
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		closeListenTestTCP(t, connection)
		t.Fatalf("connection type = %T, want *net.TCPConn", connection)
	}
	return tcpConnection
}

func closeListenTestTCP(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

var (
	errListenDiagnosticOutput = errors.New("diagnostic output failed")
	errUDPTestDiagnostic      = errors.New("UDP diagnostic failed")
	errUDPTestOutput          = errors.New("UDP output failed")
)

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

func newNetConnectTestCommand(t *testing.T, protocol string) *cobra.Command {
	t.Helper()
	command := newNetConnectCmd(commandio.NewLifecycle())
	setNetTestProtocol(t, command, protocol)
	return command
}

func newNetListenTestCommand(t *testing.T, protocol string) *cobra.Command {
	t.Helper()
	command := newNetListenCmd(commandio.NewLifecycle())
	setNetTestProtocol(t, command, protocol)
	return command
}

func setNetTestProtocol(t *testing.T, command *cobra.Command, protocol string) {
	t.Helper()
	for _, selector := range []string{"udp", "tls"} {
		if command.Flags().Lookup(selector) == nil {
			t.Fatalf("net %s has no --%s flag", command.Name(), selector)
		}
		require.NoError(t, command.Flags().Set(selector, strconv.FormatBool(selector == protocol)))
	}
}
