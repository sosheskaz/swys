package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var netListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for one incoming connection",
}

var netListenTCPCmd = binaryOutputCommand(listenStreamNetworkCommand(&cobra.Command{
	Use:   "tcp host:port",
	Short: "Exchange raw bytes over one accepted TCP connection",
	RunE:  runNetListenTCP,
}), true)

var netListenTLSCmd = binaryOutputCommand(listenTLSStreamNetworkCommand(&cobra.Command{
	Use:   "tls host:port",
	Short: "Exchange raw bytes over one accepted TLS connection",
	Long: `Exchange raw application bytes over one accepted TLS connection.

--cert and --key provide the required server identity. Supplying --ca requires
and verifies a client certificate; add --system-ca to combine the supplied
bundle with system roots. No ALPN protocols are advertised by default.`,
	RunE: runNetListenTLS,
}), true)

func runNetListenTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	listener, err := netconn.ListenTCP(setupContext, args[0])
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

	listener, err := netconn.ListenTCP(setupContext, args[0])
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

func init() {
	netCmd.AddCommand(netListenCmd)
	netListenCmd.AddCommand(netListenTCPCmd, netListenTLSCmd)

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
