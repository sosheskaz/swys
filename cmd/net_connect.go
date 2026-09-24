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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/netconn"
)

const (
	networkNoValue        = "(none)"
	tlsCertFlagName       = "cert"
	tlsKeyFlagName        = "key"
	tlsCAFlagName         = "ca"
	tlsServerNameFlagName = "servername"
)

func newNetCmd() *cobra.Command {
	netCmd := &cobra.Command{
		Aliases: []string{"nc", "netcat"},
		Use:     "net",
		Short:   "Exchange bytes over network transports",
	}
	netCmd.AddCommand(newNetConnectCmd(), newNetListenCmd())
	return netCmd
}

func newNetConnectCmd() *cobra.Command {
	command := binaryOutputCommand(streamNetworkCommandWithTimeout(&cobra.Command{
		Use:   "connect host:port",
		Short: "Exchange raw bytes with a remote TCP, UDP, or TLS endpoint",
		Long: `Connect to a remote endpoint using TCP by default, --udp for UDP, or --tls for TLS.

TCP and TLS exchange application bytes until response EOF. UDP sends one decoded
request datagram and writes the first response datagram. Input must reach EOF
before UDP sends. TLS verifies certificates and hostnames by default; --ca
replaces system roots unless --system-ca is set. Use --alpn to advertise TLS
protocols explicitly; it does not transform the application payload.`,
		RunE: runNetConnect,
	}, defaultStreamConnectTimeout,
		"TCP or UDP setup and TLS handshake timeout (0 disables)", false), true)
	command.Flags().BoolP(netProtocolUDP, "u", false, "use UDP datagrams instead of TCP")
	command.Flags().BoolP(netProtocolTLS, "T", false, "use a verified TLS stream instead of TCP")
	command.Flags().Lookup(netCloseWriteFlagName).Usage += netStreamOnlyHelp
	command.Flags().Lookup(netDuplexFlagName).Usage += netStreamOnlyHelp
	command.Flags().Lookup(netWaitFlagName).Usage =
		"response wait: TCP/TLS drain defaults to 0 (unlimited); " +
			"UDP first datagram defaults to 5s (explicit 0 waits indefinitely)"
	command.Flags().String(tlsCertFlagName, "", "TLS client certificate chain PEM path (TLS only)")
	command.Flags().String(tlsKeyFlagName, "", "TLS client private key path (TLS only)")
	command.Flags().String(tlsCAFlagName, "", "TLS custom CA certificate bundle PEM path (TLS only)")
	command.Flags().Bool(netSystemCAFlagName, false, "include system roots with --ca (TLS only)")
	command.Flags().String(tlsServerNameFlagName, "", "TLS SNI and verification name (default endpoint host; TLS only)")
	command.Flags().String(netALPNFlagName, "", "comma-separated TLS ALPN protocols (empty disables; TLS only)")
	command.Flags().Bool(netInsecureFlagName, false, "disable TLS certificate and hostname verification (TLS only)")
	registerNoFileFlagCompletion(command, tlsServerNameFlagName)
	registerALPNCompletion(command)
	configureTLSConnectFlagCompletion(command)
	for _, name := range []string{tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	registerNetDefaultValueCompletions(command)
	configureNetProtocolCompletion(command, false)
	addCommandShape(command, netProtocolShape)
	command.Args = netProtocolAddressArgs(nil, false)
	return command
}

func runNetConnect(cmd *cobra.Command, args []string) error {
	protocol, err := networkProtocolFromCommand(cmd)
	if err != nil {
		return err
	}
	switch protocol {
	case netProtocolTCP:
		return runNetConnectTCP(cmd, args)
	case netProtocolUDP:
		return runNetConnectUDP(cmd, args)
	case netProtocolTLS:
		return runNetConnectTLS(cmd, args)
	default:
		panic("validated network protocol")
	}
}

type networkStreamOptions struct {
	timeout     time.Duration
	wait        time.Duration
	closeWrite  bool
	duplex      bool
	receiveOnly bool
	verbose     bool
}

type networkDatagramConnectOptions struct {
	timeout time.Duration
	wait    time.Duration
	verbose bool
}

func runNetConnectTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	connection, err := netconn.DialTCPRetryRefused(setupContext, args[0])
	cancel()
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPConnectionDetails(cmd.ErrOrStderr(), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.RelayWithOptions(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		netconn.RelayOptions{Wait: options.wait, CloseWrite: options.closeWrite, Duplex: options.duplex},
	)
}

func runNetConnectUDP(cmd *cobra.Command, args []string) error {
	options, err := networkDatagramConnectOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	connection, err := netconn.DialUDP(setupContext, args[0])
	cancel()
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeUDPConnectionDetails(cmd.ErrOrStderr(), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	exchangeErr := exchangeUDPDatagram(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		options.wait,
	)
	return errors.Join(exchangeErr, connection.Close())
}

func exchangeUDPDatagram(
	ctx context.Context,
	connection *net.UDPConn,
	input io.Reader,
	output io.Writer,
	wait time.Duration,
) error {
	payload, err := netconn.ReadDatagramContext(ctx, input)
	if err != nil {
		return err
	}
	if err := netconn.SendUDP(ctx, connection, payload); err != nil {
		return err
	}
	responseContext, cancel := networkSetupContext(ctx, wait)
	response, err := netconn.ReceiveUDP(responseContext, connection)
	cancel()
	if err != nil {
		if wait > 0 && errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w after %s: %w", netconn.ErrUDPResponseTimeout, wait, err)
		}
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(response)); err != nil {
		return fmt.Errorf("write UDP response: %w", err)
	}
	return nil
}

func networkDatagramConnectOptionsFromCommand(cmd *cobra.Command) (networkDatagramConnectOptions, error) {
	timeout, err := cmd.Flags().GetDuration(netTimeoutFlagName)
	if err != nil {
		return networkDatagramConnectOptions{}, fmt.Errorf("read timeout flag: %w", err)
	}
	wait, err := netConnectWait(cmd)
	if err != nil {
		return networkDatagramConnectOptions{}, err
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return networkDatagramConnectOptions{}, fmt.Errorf("read verbose flag: %w", err)
	}
	return networkDatagramConnectOptions{timeout: timeout, wait: wait, verbose: verbose}, nil
}

func runNetConnectTLS(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	config, err := tlsConfigFromCommand(cmd, args[0])
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	connection, err := netconn.DialTLSRetryRefused(setupContext, args[0], config)
	cancel()
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSConnectionDetails(cmd.ErrOrStderr(), connection, config); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.RelayWithOptions(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		netconn.RelayOptions{Wait: options.wait, CloseWrite: options.closeWrite, Duplex: options.duplex},
	)
}

func networkStreamOptionsFromCommand(cmd *cobra.Command) (networkStreamOptions, error) {
	timeout, err := cmd.Flags().GetDuration(netTimeoutFlagName)
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read timeout flag: %w", err)
	}
	wait, err := cmd.Flags().GetDuration(netWaitFlagName)
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read wait flag: %w", err)
	}
	closeWrite, err := cmd.Flags().GetBool(netCloseWriteFlagName)
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read close-write flag: %w", err)
	}
	duplex, err := cmd.Flags().GetBool(netDuplexFlagName)
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read duplex flag: %w", err)
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read verbose flag: %w", err)
	}
	receiveOnly := false
	if cmd.Flags().Lookup(netRecvOnlyFlagName) != nil {
		receiveOnly, err = cmd.Flags().GetBool(netRecvOnlyFlagName)
		if err != nil {
			return networkStreamOptions{}, fmt.Errorf("read recv-only flag: %w", err)
		}
	}
	return networkStreamOptions{
		timeout:     timeout,
		wait:        wait,
		closeWrite:  closeWrite,
		duplex:      duplex,
		receiveOnly: receiveOnly,
		verbose:     verbose,
	}, nil
}

func tlsConfigFromCommand(cmd *cobra.Command, address string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address %q: %w", address, err)
	}
	serverName, err := cmd.Flags().GetString(tlsServerNameFlagName)
	if err != nil {
		return nil, fmt.Errorf("read servername flag: %w", err)
	}
	if serverName == "" {
		serverName = host
	}
	alpnText, err := cmd.Flags().GetString(netALPNFlagName)
	if err != nil {
		return nil, fmt.Errorf("read alpn flag: %w", err)
	}
	alpn, err := parseALPN(alpnText)
	if err != nil {
		return nil, err
	}
	insecure, err := cmd.Flags().GetBool(netInsecureFlagName)
	if err != nil {
		return nil, fmt.Errorf("read insecure flag: %w", err)
	}
	config := &tls.Config{ServerName: serverName, NextProtos: alpn}
	config.InsecureSkipVerify = insecure

	if err := addTLSRootCAs(cmd, config); err != nil {
		return nil, err
	}
	identity, hasIdentity, err := tlsClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if hasIdentity {
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}

func addTLSRootCAs(cmd *cobra.Command, config *tls.Config) error {
	roots, configured, err := tlsCAPoolFromCommand(cmd)
	if err != nil {
		return err
	}
	if configured {
		config.RootCAs = roots
	}
	return nil
}

func tlsCAPoolFromCommand(cmd *cobra.Command) (*x509.CertPool, bool, error) {
	caPath, err := cmd.Flags().GetString(tlsCAFlagName)
	if err != nil {
		return nil, false, fmt.Errorf("read ca flag: %w", err)
	}
	if caPath == "" {
		return nil, false, nil
	}
	systemCA, err := cmd.Flags().GetBool(netSystemCAFlagName)
	if err != nil {
		return nil, false, fmt.Errorf("read system-ca flag: %w", err)
	}
	roots := x509.NewCertPool()
	if systemCA {
		systemRoots, poolErr := x509.SystemCertPool()
		if poolErr != nil {
			return nil, false, fmt.Errorf("load system certificate pool: %w", poolErr)
		}
		roots = systemRoots.Clone()
	}
	data, err := readNetworkArtifact("--ca", caPath, maxCertificateArtifactBytes)
	if err != nil {
		return nil, false, err
	}
	certificates, err := parsePEMCertificates(data)
	if err != nil {
		return nil, false, fmt.Errorf("parse --ca: %w", err)
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	return roots, true, nil
}

func tlsClientIdentityFromCommand(cmd *cobra.Command) (tls.Certificate, bool, error) {
	return tlsIdentityFromCommand(cmd, errTLSClientKeyMismatch)
}

func tlsIdentityFromCommand(cmd *cobra.Command, mismatchError error) (tls.Certificate, bool, error) {
	certPath, err := cmd.Flags().GetString(tlsCertFlagName)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read cert flag: %w", err)
	}
	if certPath == "" {
		return tls.Certificate{}, false, nil
	}
	keyPath, err := cmd.Flags().GetString(tlsKeyFlagName)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read key flag: %w", err)
	}
	certData, err := readNetworkArtifact("--cert", certPath, maxCertificateArtifactBytes)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	certificates, err := parsePEMCertificates(certData)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse --cert: %w", err)
	}
	keyData, err := readNetworkArtifact("--key", keyPath, maxKeyArtifactBytes)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	key, err := asym.ParseKey(keyData)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse --key: %w", err)
	}
	signer, err := key.Signer()
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("validate --key private signing material: %w", err)
	}
	if err := validateTLSIdentityMatch(certificates[0], signer.Public(), mismatchError); err != nil {
		return tls.Certificate{}, false, err
	}
	chain := make([][]byte, len(certificates))
	for i, certificate := range certificates {
		chain[i] = certificate.Raw
	}
	return tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: certificates[0]}, true, nil
}

func validateTLSIdentityMatch(certificate *x509.Certificate, publicKey any, mismatchError error) error {
	certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal --cert public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal --key public part: %w", err)
	}
	if !bytes.Equal(certificateDER, keyDER) {
		return mismatchError
	}
	return nil
}

func readNetworkArtifact(flagName, path string, limit int64) ([]byte, error) {
	data, err := readArtifactFile(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", flagName, path, err)
	}
	return data, nil
}

func parseALPN(text string) ([]string, error) {
	if text == "" {
		return nil, nil
	}
	protocols := strings.Split(text, ",")
	for _, protocol := range protocols {
		if protocol == "" || protocol != strings.TrimSpace(protocol) || len(protocol) > 255 {
			return nil, fmt.Errorf("%w: --alpn values must be 1-255 bytes with no surrounding whitespace", errInvalidNetworkFlags)
		}
	}
	return protocols, nil
}

func writeTCPConnectionDetails(output io.Writer, connection net.Conn) error {
	if _, err := fmt.Fprintf(output, "connected tcp %s -> %s\n", connection.LocalAddr(), connection.RemoteAddr()); err != nil {
		return fmt.Errorf("write TCP connection details: %w", err)
	}
	return nil
}

func writeUDPConnectionDetails(output io.Writer, connection net.Conn) error {
	if _, err := fmt.Fprintf(output, "connected udp %s -> %s\n", connection.LocalAddr(), connection.RemoteAddr()); err != nil {
		return fmt.Errorf("write UDP connection details: %w", err)
	}
	return nil
}

func writeTLSConnectionDetails(output io.Writer, connection *tls.Conn, config *tls.Config) error {
	if config.InsecureSkipVerify {
		if _, err := fmt.Fprintln(output, "warning: TLS certificate verification is disabled"); err != nil {
			return fmt.Errorf("write TLS verification warning: %w", err)
		}
	}
	if _, err := fmt.Fprintf(output, "connected tls %s -> %s\n", connection.LocalAddr(), connection.RemoteAddr()); err != nil {
		return fmt.Errorf("write TLS connection summary: %w", err)
	}
	state := connection.ConnectionState()
	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = networkNoValue
	} else {
		alpn = escapeNetworkDiagnosticValue(alpn)
	}
	fields := []struct{ label, value string }{
		{label: "version", value: tls.VersionName(state.Version)},
		{label: "cipher", value: tls.CipherSuiteName(state.CipherSuite)},
		{label: netALPNFlagName, value: alpn},
		{label: "server name", value: config.ServerName},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(output, "  %s: %s\n", field.label, field.value); err != nil {
			return fmt.Errorf("write TLS %s detail: %w", field.label, err)
		}
	}
	return nil
}

func validateNetFlagsBeforeIO(cmd *cobra.Command) error {
	if !commandHasShape(cmd, networkShape) {
		return nil
	}
	timeout, err := cmd.Flags().GetDuration(netTimeoutFlagName)
	if err != nil {
		return fmt.Errorf("read timeout flag: %w", err)
	}
	if timeout < 0 {
		return fmt.Errorf("%w: --timeout cannot be negative", errInvalidNetworkFlags)
	}
	if cmd.Flags().Lookup(netWaitFlagName) != nil {
		wait, err := cmd.Flags().GetDuration(netWaitFlagName)
		if err != nil {
			return fmt.Errorf("read wait flag: %w", err)
		}
		if wait < 0 {
			return fmt.Errorf("%w: --wait cannot be negative", errInvalidNetworkFlags)
		}
	}
	if cmd.Flags().Lookup(netRecvOnlyFlagName) != nil {
		receiveOnly, err := cmd.Flags().GetBool(netRecvOnlyFlagName)
		if err != nil {
			return fmt.Errorf("read recv-only flag: %w", err)
		}
		if receiveOnly && cmd.Flags().Changed(netDuplexFlagName) {
			return fmt.Errorf("%w: --recv-only cannot be combined with --duplex", errInvalidNetworkFlags)
		}
		if receiveOnly && cmd.Flags().Changed("input") {
			return fmt.Errorf("%w: --recv-only cannot be combined with --input", errInvalidNetworkFlags)
		}
	}
	if commandHasShape(cmd, netProtocolShape) {
		return validateNetProtocolFlagsBeforeIO(cmd)
	}
	return nil
}

func validateTLSListenFlagsBeforeIO(cmd *cobra.Command) error {
	certPath, err := cmd.Flags().GetString(tlsCertFlagName)
	if err != nil {
		return fmt.Errorf("read cert flag: %w", err)
	}
	keyPath, err := cmd.Flags().GetString(tlsKeyFlagName)
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("%w: required flags --cert and --key must be specified together for TLS listeners", errInvalidNetworkFlags)
	}
	caPath, err := cmd.Flags().GetString(tlsCAFlagName)
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	systemCA, err := cmd.Flags().GetBool(netSystemCAFlagName)
	if err != nil {
		return fmt.Errorf("read system-ca flag: %w", err)
	}
	if systemCA && caPath == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", errInvalidNetworkFlags)
	}
	alpn, err := cmd.Flags().GetString(netALPNFlagName)
	if err != nil {
		return fmt.Errorf("read alpn flag: %w", err)
	}
	if _, err := parseALPN(alpn); err != nil {
		return err
	}
	return validateCertificatePaths(cmd, tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName)
}

func validateTLSFlagsBeforeIO(cmd *cobra.Command) error {
	certPath, err := cmd.Flags().GetString(tlsCertFlagName)
	if err != nil {
		return fmt.Errorf("read cert flag: %w", err)
	}
	keyPath, err := cmd.Flags().GetString(tlsKeyFlagName)
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if (certPath == "") != (keyPath == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", errInvalidNetworkFlags)
	}
	caPath, err := cmd.Flags().GetString(tlsCAFlagName)
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	systemCA, err := cmd.Flags().GetBool(netSystemCAFlagName)
	if err != nil {
		return fmt.Errorf("read system-ca flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool(netInsecureFlagName)
	if err != nil {
		return fmt.Errorf("read insecure flag: %w", err)
	}
	if insecure && (caPath != "" || systemCA) {
		return fmt.Errorf("%w: --insecure cannot be combined with --ca or --system-ca", errInvalidNetworkFlags)
	}
	if systemCA && caPath == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", errInvalidNetworkFlags)
	}
	alpn, err := cmd.Flags().GetString(netALPNFlagName)
	if err != nil {
		return fmt.Errorf("read alpn flag: %w", err)
	}
	if _, err := parseALPN(alpn); err != nil {
		return err
	}
	return validateCertificatePaths(cmd, tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName)
}
