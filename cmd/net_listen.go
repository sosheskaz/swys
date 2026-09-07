package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var netListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for one incoming connection",
}

var netListenTCPCmd = binaryOutputCommand(listenStreamNetworkCommand(&cobra.Command{
	Use:   "tcp [host:]port",
	Short: "Exchange raw bytes over one accepted TCP connection",
	RunE:  runNetListenTCP,
}), true)

var netListenUDPCmd = binaryOutputCommand(listenDatagramNetworkCommand(&cobra.Command{
	Use:   "udp [host:]port",
	Short: "Exchange one raw UDP request and response datagram",
	Long: `Exchange exactly one request and one response datagram over UDP.

The listener writes the first received datagram to stdout or --output. Decoded
stdin or --input then becomes one response datagram to that same peer, including
when the response is empty. Response input must reach EOF before it is sent;
pressing Enter alone does not send it. Omit the host to bind all available local
IPv4 and IPv6 addresses.`,
	RunE: runNetListenUDP,
}), true)

var netListenTLSCmd = binaryOutputCommand(listenTLSStreamNetworkCommand(&cobra.Command{
	Use:   "tls [host:]port",
	Short: "Exchange raw bytes over one accepted TLS connection",
	Long: `Exchange raw application bytes over one accepted TLS connection.

--cert and --key provide the required server identity. Supplying --ca requires
and verifies a client certificate; add --system-ca to combine the supplied
bundle with system roots. No ALPN protocols are advertised by default. Omit
the host by passing only the numeric port to listen on all available local
IPv4 and IPv6 addresses.`,
	RunE: runNetListenTLS,
}), true)

func runNetListenTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	address, err := normalizeListenAddress(args[0])
	if err != nil {
		return err
	}
	listener, err := netconn.ListenTCP(setupContext, address)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPListeningDetails(cmd.ErrOrStderr(), listener); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	connection, err := netconn.AcceptTCP(setupContext, listener)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPAcceptedDetails(cmd.ErrOrStderr(), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.Relay(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		options.wait,
		options.closeWrite,
	)
}

func runNetListenUDP(cmd *cobra.Command, args []string) error {
	options, err := networkDatagramListenOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	address, err := normalizeListenAddress(args[0])
	if err != nil {
		cancel()
		return err
	}
	listener, err := netconn.ListenUDP(setupContext, address)
	if err != nil {
		cancel()
		return err
	}
	if options.verbose {
		if err := writeUDPListeningDetails(cmd.ErrOrStderr(), listener); err != nil {
			cancel()
			return errors.Join(err, listener.Close())
		}
	}
	request, peer, err := netconn.ReceiveUDPFrom(setupContext, listener)
	cancel()
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	if options.verbose {
		if err := writeUDPReceivedDetails(cmd.ErrOrStderr(), listener.LocalAddr(), peer); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	exchangeErr := respondUDPDatagram(
		cmd.Context(),
		listener,
		peer,
		request,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
	)
	return errors.Join(exchangeErr, listener.Close())
}

type networkDatagramListenOptions struct {
	timeout time.Duration
	verbose bool
}

func networkDatagramListenOptionsFromCommand(cmd *cobra.Command) (networkDatagramListenOptions, error) {
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return networkDatagramListenOptions{}, fmt.Errorf("read timeout flag: %w", err)
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return networkDatagramListenOptions{}, fmt.Errorf("read verbose flag: %w", err)
	}
	return networkDatagramListenOptions{timeout: timeout, verbose: verbose}, nil
}

func respondUDPDatagram(
	ctx context.Context,
	connection *net.UDPConn,
	peer *net.UDPAddr,
	request []byte,
	input io.Reader,
	output io.Writer,
) error {
	if _, err := io.Copy(output, bytes.NewReader(request)); err != nil {
		return fmt.Errorf("write UDP request: %w", err)
	}
	if err := finalizeOutputEncoding(output); err != nil {
		return fmt.Errorf("finalize UDP request output encoding: %w", err)
	}
	response, err := netconn.ReadDatagramContext(ctx, input)
	if err != nil {
		return err
	}
	return netconn.SendUDPTo(ctx, connection, response, peer)
}

func runNetListenTLS(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	config, err := tlsServerConfigFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	address, err := normalizeListenAddress(args[0])
	if err != nil {
		return err
	}
	listener, err := netconn.ListenTCP(setupContext, address)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSListeningDetails(cmd.ErrOrStderr(), listener); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	connection, err := netconn.AcceptTLS(setupContext, listener, config)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSAcceptedDetails(cmd.ErrOrStderr(), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.Relay(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		options.wait,
		options.closeWrite,
	)
}

func tlsServerConfigFromCommand(cmd *cobra.Command) (*tls.Config, error) {
	identity, hasIdentity, err := tlsIdentityFromCommand(cmd, errTLSServerKeyMismatch)
	if err != nil {
		return nil, err
	}
	if !hasIdentity {
		return nil, fmt.Errorf("%w: --cert and --key are required", errInvalidNetworkFlags)
	}
	if err := validateTLSServerIdentity(&identity); err != nil {
		return nil, err
	}
	alpnText, err := cmd.Flags().GetString("alpn")
	if err != nil {
		return nil, fmt.Errorf("read alpn flag: %w", err)
	}
	alpn, err := parseALPN(alpnText)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{identity}, NextProtos: alpn}
	clientRoots, requireClient, err := tlsCAPoolFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if requireClient {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = clientRoots
	}
	return config, nil
}

func validateTLSServerIdentity(identity *tls.Certificate) error {
	if len(identity.Certificate) == 0 {
		return fmt.Errorf("validate --cert server certificate chain: %w", errNoPEMCertificates)
	}
	certificates := make([]*x509.Certificate, len(identity.Certificate))
	for i, der := range identity.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("validate --cert certificate %d: %w", i+1, err)
		}
		certificates[i] = certificate
	}
	for i := range len(certificates) - 1 {
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return fmt.Errorf(
				"validate --cert server certificate chain: presented certificate %d does not certify certificate %d: %w",
				i+2,
				i+1,
				err,
			)
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	intermediates := x509.NewCertPool()
	if len(certificates) > 2 {
		for _, certificate := range certificates[1 : len(certificates)-1] {
			intermediates.AddCert(certificate)
		}
	}
	if _, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("validate --cert server certificate chain: %w", err)
	}
	return nil
}

func writeTCPListeningDetails(output io.Writer, listener net.Listener) error {
	if _, err := fmt.Fprintf(output, "listening tcp %s\n", listener.Addr()); err != nil {
		return fmt.Errorf("write TCP listener details: %w", err)
	}
	return nil
}

func writeUDPListeningDetails(output io.Writer, listener net.PacketConn) error {
	if _, err := fmt.Fprintf(output, "listening udp %s\n", listener.LocalAddr()); err != nil {
		return fmt.Errorf("write UDP listener details: %w", err)
	}
	return nil
}

func writeUDPReceivedDetails(output io.Writer, local, remote net.Addr) error {
	if _, err := fmt.Fprintf(output, "received udp %s <- %s\n", local, remote); err != nil {
		return fmt.Errorf("write received UDP datagram details: %w", err)
	}
	return nil
}

func writeTCPAcceptedDetails(output io.Writer, connection net.Conn) error {
	if _, err := fmt.Fprintf(
		output,
		"accepted tcp %s <- %s\n",
		connection.LocalAddr(),
		connection.RemoteAddr(),
	); err != nil {
		return fmt.Errorf("write accepted TCP connection details: %w", err)
	}
	return nil
}

func writeTLSListeningDetails(output io.Writer, listener net.Listener) error {
	if _, err := fmt.Fprintf(output, "listening tls %s\n", listener.Addr()); err != nil {
		return fmt.Errorf("write TLS listener details: %w", err)
	}
	return nil
}

func writeTLSAcceptedDetails(output io.Writer, connection *tls.Conn) error {
	if _, err := fmt.Fprintf(
		output,
		"accepted tls %s <- %s\n",
		connection.LocalAddr(),
		connection.RemoteAddr(),
	); err != nil {
		return fmt.Errorf("write accepted TLS connection details: %w", err)
	}
	state := connection.ConnectionState()
	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = networkNoValue
	}
	serverName := state.ServerName
	if serverName == "" {
		serverName = networkNoValue
	} else {
		serverName = escapeNetworkDiagnosticValue(serverName)
	}
	clientVerified := "no"
	if len(state.VerifiedChains) > 0 {
		clientVerified = "yes"
	}
	fields := []struct{ label, value string }{
		{label: "version", value: tls.VersionName(state.Version)},
		{label: "cipher", value: tls.CipherSuiteName(state.CipherSuite)},
		{label: "alpn", value: alpn},
		{label: "sni", value: serverName},
		{label: "peer certificates", value: strconv.Itoa(len(state.PeerCertificates))},
		{label: "client chain verified", value: clientVerified},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(output, "  %s: %s\n", field.label, field.value); err != nil {
			return fmt.Errorf("write TLS %s detail: %w", field.label, err)
		}
	}
	return nil
}

func escapeNetworkDiagnosticValue(value string) string {
	quoted := strconv.Quote(value)
	return quoted[1 : len(quoted)-1]
}

func init() {
	netCmd.AddCommand(netListenCmd)
	netListenCmd.AddCommand(netListenTCPCmd, netListenTLSCmd, netListenUDPCmd)

	netListenTLSCmd.Flags().String(tlsCertFlagName, "", "server certificate chain PEM path")
	netListenTLSCmd.Flags().String(tlsKeyFlagName, "", "server private key path")
	netListenTLSCmd.Flags().String(tlsCAFlagName, "", "client CA certificate bundle PEM path")
	netListenTLSCmd.Flags().Bool("system-ca", false, "include system roots with --ca")
	netListenTLSCmd.Flags().String("alpn", "", "comma-separated ALPN protocols (empty disables)")
	for _, name := range []string{tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName} {
		if err := netListenTLSCmd.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{tlsCertFlagName, tlsKeyFlagName} {
		if err := netListenTLSCmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
