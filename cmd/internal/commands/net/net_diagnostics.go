package net

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

func writeTCPConnectionDetails(output io.Writer, options textdisplay.Options, connection net.Conn) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("connected tcp %s -> %s", connection.LocalAddr(), connection.RemoteAddr()))
}

func writeUDPConnectionDetails(output io.Writer, options textdisplay.Options, connection net.Conn) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("connected udp %s -> %s", connection.LocalAddr(), connection.RemoteAddr()))
}

func writeTCPListeningDetails(output io.Writer, options textdisplay.Options, listener net.Listener) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("listening tcp %s", listener.Addr()))
}

func writeUDPListeningDetails(output io.Writer, options textdisplay.Options, listener net.PacketConn) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("listening udp %s", listener.LocalAddr()))
}

func writeUDPReceivedDetails(output io.Writer, options textdisplay.Options, local, remote net.Addr) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("received udp %s <- %s", local, remote))
}

func writeTCPAcceptedDetails(output io.Writer, options textdisplay.Options, connection net.Conn) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("accepted tcp %s <- %s", connection.LocalAddr(), connection.RemoteAddr()))
}

func writeTLSListeningDetails(output io.Writer, options textdisplay.Options, listener net.Listener) error {
	return writeNetworkEvent(output, options, fmt.Sprintf("listening tls %s", listener.Addr()))
}

func writeNetworkEvent(output io.Writer, options textdisplay.Options, event string) error {
	printer := textdisplay.New(output, options)
	printer.Line(event, textdisplay.Strong)
	return printer.Err()
}

func writeTLSConnectionDetails(output io.Writer, options textdisplay.Options, connection *tls.Conn, config *tls.Config) error {
	printer := textdisplay.New(output, options)
	if config.InsecureSkipVerify {
		printer.Line("warning: TLS certificate verification is disabled", textdisplay.Warning)
	}
	printer.Heading(fmt.Sprintf("connected tls %s -> %s", connection.LocalAddr(), connection.RemoteAddr()))
	state := connection.ConnectionState()
	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = networkNoValue
	}
	printer.Section("TLS")
	printer.Fields([]textdisplay.Field{
		{Label: "version", Value: tls.VersionName(state.Version)},
		{Label: "cipher", Value: tls.CipherSuiteName(state.CipherSuite)},
		{Label: netALPNFlagName, Value: escapeNetworkDiagnosticValue(alpn)},
		{Label: "server name", Value: escapeNetworkDiagnosticValue(config.ServerName)},
	})
	return printer.Err()
}

func writeTLSAcceptedDetails(output io.Writer, options textdisplay.Options, connection *tls.Conn) error {
	printer := textdisplay.New(output, options)
	printer.Heading(fmt.Sprintf("accepted tls %s <- %s", connection.LocalAddr(), connection.RemoteAddr()))
	state := connection.ConnectionState()
	alpn, serverName := state.NegotiatedProtocol, state.ServerName
	if alpn == "" {
		alpn = networkNoValue
	}
	if serverName == "" {
		serverName = networkNoValue
	}
	clientVerified := "no"
	if len(state.VerifiedChains) > 0 {
		clientVerified = "yes"
	}
	printer.Section("TLS")
	printer.Fields([]textdisplay.Field{
		{Label: "version", Value: tls.VersionName(state.Version)},
		{Label: "cipher", Value: tls.CipherSuiteName(state.CipherSuite)},
		{Label: netALPNFlagName, Value: escapeNetworkDiagnosticValue(alpn)},
		{Label: "sni", Value: escapeNetworkDiagnosticValue(serverName)},
		{Label: "peer certificates", Value: strconv.Itoa(len(state.PeerCertificates))},
		{Label: "client chain verified", Value: clientVerified},
	})
	return printer.Err()
}

func escapeNetworkDiagnosticValue(value string) string {
	quoted := strconv.Quote(value)
	return quoted[1 : len(quoted)-1]
}
