package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var netCmd = &cobra.Command{
	Aliases: []string{"nc", "netcat"},
	Use:     "net",
	Short:   "Exchange bytes over network transports",
}

var netConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a remote endpoint",
}

var netConnectTCPCmd = binaryOutputCommand(streamNetworkCommand(&cobra.Command{
	Use:   "tcp host:port",
	Short: "Exchange raw bytes over TCP",
	RunE:  runNetConnectTCP,
}), true)

var netConnectTLSCmd = binaryOutputCommand(streamNetworkCommand(&cobra.Command{
	Use:   "tls host:port",
	Short: "Exchange raw bytes over a verified TLS connection",
	Long: `Exchange raw application bytes over TLS.

Server certificates and hostnames are verified by default. --ca replaces the
system trust store with a PEM bundle; add --system-ca to combine both stores.
--cert and --key configure an optional mTLS client identity. --insecure disables
verification explicitly and is intended only for controlled diagnostics.

No ALPN protocols are advertised by default. Use --alpn with a comma-separated
list to advertise protocols explicitly. Negotiation does not transform the
payload: when h2 is selected, input must contain valid HTTP/2 frames.`,
	RunE: runNetConnectTLS,
}), true)

type networkStreamOptions struct {
	timeout    time.Duration
	wait       time.Duration
	closeWrite bool
	verbose    bool
}

func runNetConnectTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	connection, err := netconn.DialTCP(setupContext, args[0])
	cancel()
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPConnectionDetails(cmd.ErrOrStderr(), connection); err != nil {
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
	connection, err := netconn.DialTLS(setupContext, args[0], config)
	cancel()
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSConnectionDetails(cmd.ErrOrStderr(), connection, config); err != nil {
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

func networkStreamOptionsFromCommand(cmd *cobra.Command) (networkStreamOptions, error) {
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read timeout flag: %w", err)
	}
	wait, err := cmd.Flags().GetDuration("wait")
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read wait flag: %w", err)
	}
	closeWrite, err := cmd.Flags().GetBool("close-write")
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read close-write flag: %w", err)
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return networkStreamOptions{}, fmt.Errorf("read verbose flag: %w", err)
	}
	return networkStreamOptions{
		timeout:    timeout,
		wait:       wait,
		closeWrite: closeWrite,
		verbose:    verbose,
	}, nil
}

func tlsConfigFromCommand(cmd *cobra.Command, address string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address %q: %w", address, err)
	}
	serverName, err := cmd.Flags().GetString("servername")
	if err != nil {
		return nil, fmt.Errorf("read servername flag: %w", err)
	}
	if serverName == "" {
		serverName = host
	}
	alpnText, err := cmd.Flags().GetString("alpn")
	if err != nil {
		return nil, fmt.Errorf("read alpn flag: %w", err)
	}
	alpn, err := parseALPN(alpnText)
	if err != nil {
		return nil, err
	}
	insecure, err := cmd.Flags().GetBool("insecure")
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
	caPath, err := cmd.Flags().GetString("ca")
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	if caPath == "" {
		return nil
	}
	systemCA, err := cmd.Flags().GetBool("system-ca")
	if err != nil {
		return fmt.Errorf("read system-ca flag: %w", err)
	}
	roots := x509.NewCertPool()
	if systemCA {
		systemRoots, poolErr := x509.SystemCertPool()
		if poolErr != nil {
			return fmt.Errorf("load system certificate pool: %w", poolErr)
		}
		roots = systemRoots.Clone()
	}
	data, err := readNetworkArtifact("--ca", caPath)
	if err != nil {
		return err
	}
	certificates, err := parsePEMCertificates(data)
	if err != nil {
		return fmt.Errorf("parse --ca: %w", err)
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	config.RootCAs = roots
	return nil
}

func tlsClientIdentityFromCommand(cmd *cobra.Command) (tls.Certificate, bool, error) {
	certPath, err := cmd.Flags().GetString("cert")
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read cert flag: %w", err)
	}
	if certPath == "" {
		return tls.Certificate{}, false, nil
	}
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read key flag: %w", err)
	}
	certData, err := readNetworkArtifact("--cert", certPath)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	certificates, err := parsePEMCertificates(certData)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse --cert: %w", err)
	}
	keyData, err := readNetworkArtifact("--key", keyPath)
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
	if err := validateTLSIdentityMatch(certificates[0], signer.Public()); err != nil {
		return tls.Certificate{}, false, err
	}
	chain := make([][]byte, len(certificates))
	for i, certificate := range certificates {
		chain[i] = certificate.Raw
	}
	return tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: certificates[0]}, true, nil
}

func validateTLSIdentityMatch(certificate *x509.Certificate, publicKey any) error {
	certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal --cert public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal --key public part: %w", err)
	}
	if !bytes.Equal(certificateDER, keyDER) {
		return errTLSClientKeyMismatch
	}
	return nil
}

func readNetworkArtifact(flagName, path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading an explicitly selected CLI path is intended
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
		alpn = "(none)"
	}
	fields := []struct{ label, value string }{
		{label: "version", value: tls.VersionName(state.Version)},
		{label: "cipher", value: tls.CipherSuiteName(state.CipherSuite)},
		{label: "alpn", value: alpn},
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
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return fmt.Errorf("read timeout flag: %w", err)
	}
	if timeout < 0 {
		return fmt.Errorf("%w: --timeout cannot be negative", errInvalidNetworkFlags)
	}
	if cmd != netConnectTCPCmd && cmd != netConnectTLSCmd && cmd != netListenTCPCmd {
		return nil
	}
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	if options.wait < 0 {
		return fmt.Errorf("%w: --wait cannot be negative", errInvalidNetworkFlags)
	}
	if cmd == netConnectTCPCmd || cmd == netListenTCPCmd {
		return nil
	}
	return validateTLSFlagsBeforeIO(cmd)
}

func validateTLSFlagsBeforeIO(cmd *cobra.Command) error {
	certPath, err := cmd.Flags().GetString("cert")
	if err != nil {
		return fmt.Errorf("read cert flag: %w", err)
	}
	keyPath, err := cmd.Flags().GetString("key")
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if (certPath == "") != (keyPath == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", errInvalidNetworkFlags)
	}
	caPath, err := cmd.Flags().GetString("ca")
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	systemCA, err := cmd.Flags().GetBool("system-ca")
	if err != nil {
		return fmt.Errorf("read system-ca flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("read insecure flag: %w", err)
	}
	if insecure && (caPath != "" || systemCA) {
		return fmt.Errorf("%w: --insecure cannot be combined with --ca or --system-ca", errInvalidNetworkFlags)
	}
	if systemCA && caPath == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", errInvalidNetworkFlags)
	}
	alpn, err := cmd.Flags().GetString("alpn")
	if err != nil {
		return fmt.Errorf("read alpn flag: %w", err)
	}
	if _, err := parseALPN(alpn); err != nil {
		return err
	}
	return validateCertificatePaths(cmd, "cert", "key", "ca")
}

func init() {
	rootCmd.AddCommand(netCmd)
	netCmd.AddCommand(netConnectCmd)
	netConnectCmd.AddCommand(netConnectTCPCmd, netConnectTLSCmd)

	netConnectTLSCmd.Flags().String("cert", "", "client certificate chain PEM path")
	netConnectTLSCmd.Flags().String("key", "", "client private key path")
	netConnectTLSCmd.Flags().String("ca", "", "custom CA certificate bundle PEM path")
	netConnectTLSCmd.Flags().Bool("system-ca", false, "include system roots with --ca")
	netConnectTLSCmd.Flags().String("servername", "", "TLS SNI and verification name (default endpoint host)")
	netConnectTLSCmd.Flags().String("alpn", "", "comma-separated ALPN protocols (empty disables)")
	netConnectTLSCmd.Flags().Bool("insecure", false, "disable TLS certificate and hostname verification")
	for _, name := range []string{"cert", "key", "ca"} {
		if err := netConnectTLSCmd.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
}
