package net

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/netconn"
)

func newNetListenCmd(lifecycle *commandio.Lifecycle) *cobra.Command {
	command := commandio.BinaryOutputCommand(commandio.StreamNetworkCommandWithTimeout(&cobra.Command{
		Use:   "listen [host:]port",
		Short: "Serve one TCP, UDP, or TLS exchange",
		Long: `Listen for one exchange using TCP by default, --udp for UDP, or --tls for TLS.

TCP and TLS accept one stream connection; --recv-only reads peer data without
sending input. UDP writes the first request datagram and sends one decoded
response datagram to its peer. UDP uses --connect-timeout for the first datagram and
does not accept --wait. TLS requires --cert and --key for the server identity;
--ca requires and verifies a client certificate. Omit the host to bind all
available local IPv4 and IPv6 addresses.`,
		RunE: runNetListen,
	}, 0, "bind resolution, accept or first datagram, and TLS handshake timeout (0 disables)", true,
		commandio.NetworkCompletion{Applicable: netFlagValueCompletionApplicable, ZeroDescription: netDurationZeroDescription}), true)
	command.Flags().BoolP(netProtocolUDP, "u", false, "use UDP datagrams instead of TCP")
	command.Flags().BoolP(netProtocolTLS, "T", false, "use a verified TLS stream instead of TCP")
	command.Flags().Lookup(netCloseWriteFlagName).Usage += netStreamOnlyHelp
	command.Flags().Lookup(netDuplexFlagName).Usage += netStreamOnlyHelp
	command.Flags().Lookup(netWaitFlagName).Usage += " (TCP/TLS only; UDP listener uses --connect-timeout)"
	command.Flags().BoolP(netRecvOnlyFlagName, "r", false, "receive peer data without reading or sending input (TCP/TLS only)")
	command.Flags().String(tlsconfig.CertFlagName, "", "TLS server certificate chain PEM path (TLS only; required)")
	command.Flags().StringP(tlsconfig.KeyFlagName, "k", "", "TLS server private key path (TLS only; required)")
	command.Flags().String(tlsconfig.CAFlagName, "", "TLS client CA certificate bundle PEM path (TLS only)")
	command.Flags().Bool(tlsconfig.SystemCAFlagName, false, "include system roots with --ca (TLS only)")
	command.Flags().String(netALPNFlagName, "", "comma-separated TLS ALPN protocols (empty disables; TLS only)")
	registerALPNCompletion(command)
	tlsconfig.AddArtifactEncodingFlags(command, netTLSCompletionApplicable)
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	registerNetDefaultValueCompletions(command)
	configureNetProtocolCompletion(command, true)
	commandio.AddShape(command, netProtocolShape)
	command.Args = netProtocolAddressArgs(nil, true)
	lifecycle.Register(command, commandio.Behavior{
		SupportsInput: true, SupportsOutput: true, Validate: validateNetCommand,
		BeforeIO: prepareNetTLSBeforeIO(prepareNetListenTLS),
	})
	return command
}

func runNetListen(cmd *cobra.Command, args []string) error {
	protocol, err := networkProtocolFromCommand(cmd)
	if err != nil {
		return err
	}
	switch protocol {
	case netProtocolTCP:
		return runNetListenTCP(cmd, args)
	case netProtocolUDP:
		return runNetListenUDP(cmd, args)
	case netProtocolTLS:
		return runNetListenTLS(cmd, args)
	default:
		panic("validated network protocol")
	}
}

func runNetListenTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := commandio.NetworkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	address, err := commandio.NormalizeListenAddress(args[0])
	if err != nil {
		return err
	}
	listener, err := netconn.ListenTCP(setupContext, address)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPListeningDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), listener); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	connection, err := netconn.AcceptTCP(setupContext, listener)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPAcceptedDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.RelayWithOptions(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		netconn.RelayOptions{
			Wait: options.wait, CloseWrite: options.closeWrite,
			Duplex: options.duplex, ReceiveOnly: options.receiveOnly,
		},
	)
}

func runNetListenUDP(cmd *cobra.Command, args []string) error {
	options, err := networkDatagramListenOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := commandio.NetworkSetupContext(cmd.Context(), options.timeout)
	address, err := commandio.NormalizeListenAddress(args[0])
	if err != nil {
		cancel()
		return err
	}
	listener, err := netconn.ListenUDP(setupContext, address)
	if err != nil {
		cancel()
		return err
	}
	return receiveAndRespondUDPDatagram(cmd.Context(), setupContext, cancel, cmd, listener, options.verbose)
}

func receiveAndRespondUDPDatagram(
	ctx, setupContext context.Context,
	cancelSetup context.CancelFunc,
	cmd *cobra.Command,
	listener *net.UDPConn,
	verbose bool,
) error {
	if verbose {
		if err := writeUDPListeningDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), listener); err != nil {
			cancelSetup()
			return errors.Join(err, listener.Close())
		}
	}
	request, peer, err := netconn.ReceiveUDPFrom(setupContext, listener)
	cancelSetup()
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	if verbose {
		if err := writeUDPReceivedDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), listener.LocalAddr(), peer); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	exchangeErr := respondUDPDatagram(
		ctx,
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
	timeout, err := cmd.Flags().GetDuration(netConnectTimeoutFlagName)
	if err != nil {
		return networkDatagramListenOptions{}, fmt.Errorf("read connect-timeout flag: %w", err)
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
	if err := encoding.Finalize(output); err != nil {
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
	config, err := preparedTLSConfig(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := commandio.NetworkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	address, err := commandio.NormalizeListenAddress(args[0])
	if err != nil {
		return err
	}
	listener, err := netconn.ListenTCP(setupContext, address)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSListeningDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), listener); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	connection, err := netconn.AcceptTLS(setupContext, listener, config)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTLSAcceptedDetails(cmd.ErrOrStderr(), presentation.Diagnostics(cmd), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.RelayWithOptions(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		netconn.RelayOptions{
			Wait: options.wait, CloseWrite: options.closeWrite,
			Duplex: options.duplex, ReceiveOnly: options.receiveOnly,
		},
	)
}

func prepareNetListenTLS(cmd *cobra.Command) error {
	protocol, err := networkProtocolFromCommand(cmd)
	if err != nil {
		return err
	}
	if protocol != netProtocolTLS {
		return nil
	}
	config, err := tlsServerConfigFromCommand(cmd)
	if err != nil {
		return err
	}
	cmd.SetContext(context.WithValue(cmd.Context(), preparedTLSConfigKey{}, config))
	return nil
}

func tlsServerConfigFromCommand(cmd *cobra.Command) (*tls.Config, error) {
	identity, hasIdentity, err := tlsconfig.IdentityFromCommand(cmd, ErrServerKeyMismatch)
	if err != nil {
		return nil, err
	}
	if !hasIdentity {
		return nil, fmt.Errorf("%w: required flags --cert and --key are missing", ErrInvalidFlags)
	}
	if err := validateTLSServerIdentity(&identity); err != nil {
		return nil, err
	}
	alpnText, err := cmd.Flags().GetString(netALPNFlagName)
	if err != nil {
		return nil, fmt.Errorf("read alpn flag: %w", err)
	}
	alpn, err := parseALPN(alpnText)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{identity}, NextProtos: alpn}
	clientRoots, requireClient, err := tlsconfig.CAPoolFromCommand(cmd)
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
		return fmt.Errorf("validate --cert server certificate chain: %w", certinput.ErrNoCertificates)
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

// ErrServerKeyMismatch identifies a listener certificate and key mismatch.
var ErrServerKeyMismatch = errors.New("TLS server certificate and private key do not match")
