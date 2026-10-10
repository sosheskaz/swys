// Package crpc builds the Connect RPC command.
package crpc

import (
	"bytes"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpguts"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/connectrpc"
	"github.com/sosheskaz/swys/internal/httptransport"
)

//go:embed guides
var guides embed.FS

// ErrInvalidFlags identifies inconsistent request options before input or output is opened.
var ErrInvalidFlags = errors.New("invalid Connect RPC flags")

const (
	stdinAuto   = "auto"
	stdinNever  = "never"
	stdinAlways = "always"
	formatJSON  = "json"
)

type options struct {
	data, stdin, format         string
	ca, cert, key, serverName   string
	headers, resolves           []string
	connectTimeout, timeout     time.Duration
	maxMessageSize              int
	systemCA, insecure, verbose bool
}

// NewCommand constructs Connect RPC invocation and registers its I/O lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	settings := &options{}
	var pending []byte
	command := &cobra.Command{
		Use:               "crpc URL [SERVICE/METHOD]",
		Aliases:           []string{"connectrpc"},
		Short:             "Call Connect RPC services with JSON",
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			if _, err := output.Write(data); err != nil {
				return fmt.Errorf("write Connect response: %w", err)
			}
			return nil
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		SupportsInput: true, SupportsOutput: true,
		InputPrepared: true, ClearInheritedStreams: true,
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			pending = nil
			output, err := prepare(cmd, args, settings)
			if err != nil {
				return nil, err
			}
			pending = output
			return func(err error) error {
				if err != nil {
					pending = nil
					return err
				}
				commandio.AppendCleanup(cmd, func() { pending = nil })
				return nil
			}, nil
		},
		Prepare: func(*cobra.Command, io.Reader) ([]byte, error) { return pending, nil },
	})
	commandio.AddShape(command, "structured-output")
	commandio.AddShape(command, "crpc-request")
	commandio.AddShape(command, "network")
	commandio.AddInputEncodingFlag(command)
	commandio.AddOutputEncodingFlag(command)
	flags := command.Flags()
	flags.StringVarP(&settings.data, "data", "d", "", "literal JSON request")
	flags.StringVar(&settings.stdin, "stdin", stdinAuto, "read stdin: auto (non-terminal), never, or always")
	flags.StringVarP(&settings.format, "format", "f", formatJSON, "response format (json)")
	flags.StringArrayVarP(&settings.headers, "header", "H", nil, "request header (name: value); repeatable")
	flags.StringArrayVar(&settings.resolves, "resolve", nil, "override HOST:PORT with ADDRESS[,ADDRESS]; repeatable")
	flags.DurationVarP(&settings.connectTimeout, "connect-timeout", "c", commandio.DefaultNetworkTimeout, "connection and TLS setup timeout (0 disables)")
	flags.DurationVarP(&settings.timeout, "timeout", "t", 0, "whole RPC timeout after collecting input (0 disables)")
	flags.IntVar(&settings.maxMessageSize, "max-message-size", 16<<20, "maximum uncompressed JSON bytes per sent or received message")
	flags.StringVar(&settings.ca, "ca", "", "custom CA certificate bundle path; - reads stdin")
	flags.BoolVar(&settings.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&settings.cert, "cert", "", "client certificate chain path; - reads stdin")
	flags.StringVarP(&settings.key, "key", "k", "", "client private key path; - reads stdin")
	flags.StringVar(&settings.serverName, "servername", "", "override TLS SNI and verification name")
	flags.BoolVar(&settings.insecure, "insecure", false, "disable TLS certificate and hostname verification")
	flags.BoolVarP(&settings.verbose, "verbose", "v", false, "write status, response headers, and TLS details to stderr")
	commandio.RegisterFlagCompletion(command, "stdin", func() []string { return []string{stdinAuto, stdinNever, stdinAlways} })
	commandio.RegisterFlagCompletion(command, "format", func() []string { return []string{formatJSON} })
	for _, name := range []string{"connect-timeout", "timeout"} {
		commandio.RegisterDurationCompletion(command, name, "Disable this timeout", commandio.NetworkCompletion{})
	}
	for _, name := range []string{"ca", "cert", "key"} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	tlsconfig.AddArtifactEncodingFlags(command, tlsApplicable)
	tlsconfig.RegisterArtifactEncodingCompletion(lifecycle, func() *cobra.Command { return NewCommand(commandio.NewLifecycle()) }, tlsApplicable)
	if err := help.RegisterGuides(command, guides); err != nil {
		panic(err)
	}
	return command
}

func tlsApplicable(_ *cobra.Command, args []string) bool {
	return len(args) == 0 || !strings.HasPrefix(args[0], "http://")
}

func prepare(cmd *cobra.Command, args []string, settings *options) ([]byte, error) {
	method := ""
	if len(args) == 2 {
		method = args[1]
	}
	endpoint, err := connectrpc.ParseEndpoint(args[0], method)
	if err != nil {
		return nil, err
	}
	if err := validate(cmd, settings, endpoint.URL.Scheme == "https"); err != nil {
		return nil, err
	}
	headers, err := parseHeaders(settings.headers)
	if err != nil {
		return nil, err
	}
	resolver, err := httptransport.ParseResolves(settings.resolves)
	if err != nil {
		return nil, err
	}
	tlsOptions, err := prepareTLS(cmd, settings)
	if err != nil {
		return nil, err
	}
	request, err := readRequest(cmd, settings)
	if err != nil {
		return nil, err
	}
	value, err := connectrpc.ParseJSON(request)
	if err != nil {
		return nil, err
	}
	client := connectrpc.NewClient(endpoint, connectrpc.Options{
		TLS: tlsOptions, Resolves: resolver, ConnectTimeout: settings.connectTimeout, MaxMessageSize: settings.maxMessageSize,
	})
	defer client.Close()
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.timeout)
	defer cancel()
	ctx, call := connect.NewClientContext(ctx)
	for name, values := range headers.All() {
		call.RequestHeader().SetValues(name, values)
	}
	response, callErr := client.Unary(ctx, value)
	if settings.verbose {
		if err := writeDiagnostics(ctx, cmd.ErrOrStderr(), call, callErr); err != nil {
			return nil, errors.Join(safeError(callErr), err)
		}
	}
	if callErr != nil {
		return nil, safeError(callErr)
	}
	return append(response, '\n'), nil
}

func validate(cmd *cobra.Command, settings *options, secure bool) error {
	if settings.connectTimeout < 0 || settings.timeout < 0 || settings.maxMessageSize <= 0 {
		return fmt.Errorf("%w: timeouts must be non-negative and --max-message-size must be positive", ErrInvalidFlags)
	}
	if settings.format != formatJSON {
		return fmt.Errorf("%w: --format must be json", ErrInvalidFlags)
	}
	if settings.stdin != stdinAuto && settings.stdin != stdinNever && settings.stdin != stdinAlways {
		return fmt.Errorf("%w: --stdin must be auto, never, or always", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("data") && cmd.Flags().Changed("input") {
		return fmt.Errorf("%w: --data and --input are mutually exclusive", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("stdin") && settings.stdin != stdinAuto && (cmd.Flags().Changed("data") || cmd.Flags().Changed("input")) {
		return fmt.Errorf("%w: --stdin cannot accompany --data or --input", ErrInvalidFlags)
	}
	return validateTLS(cmd, settings, secure)
}

func validateTLS(cmd *cobra.Command, settings *options, secure bool) error {
	if (settings.cert == "") != (settings.key == "") {
		return fmt.Errorf("%w: --cert and --key require each other", ErrInvalidFlags)
	}
	if settings.systemCA && settings.ca == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", ErrInvalidFlags)
	}
	if !secure {
		for _, name := range []string{"ca", "system-ca", "cert", "key", "servername", "insecure"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("%w: --%s requires HTTPS", ErrInvalidFlags, name)
			}
		}
	}
	if err := tlsconfig.ValidateArtifactSources(cmd, secure, usesStdin(cmd, settings), ErrInvalidFlags); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "ca", "cert", "key")
}

func usesStdin(cmd *cobra.Command, settings *options) bool {
	if cmd.Flags().Changed("input") {
		return cmd.Flag("input").Value.String() == "-"
	}
	if cmd.Flags().Changed("data") {
		return false
	}
	return settings.stdin == stdinAlways || settings.stdin == stdinAuto && !commandio.InputIsTerminal(cmd.InOrStdin())
}

func readRequest(cmd *cobra.Command, settings *options) ([]byte, error) {
	decoder, err := commandio.InputDecoderFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	var data []byte
	switch {
	case cmd.Flags().Changed("data"):
		data, err = artifact.Read(decoder(strings.NewReader(settings.data)), int64(settings.maxMessageSize))
	case cmd.Flags().Changed("input"):
		data, err = artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), cmd.Flag("input").Value.String(), decoder, int64(settings.maxMessageSize))
	case usesStdin(cmd, settings):
		data, err = artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), "-", decoder, int64(settings.maxMessageSize))
	}
	if err != nil {
		return nil, fmt.Errorf("read Connect request: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 && !cmd.Flags().Changed("data") && !cmd.Flags().Changed("input") {
		return []byte("{}"), nil
	}
	return data, nil
}

func prepareTLS(cmd *cobra.Command, settings *options) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: settings.serverName,
		InsecureSkipVerify: settings.insecure,
	}
	if err := tlsconfig.AddRootCAs(cmd, config); err != nil {
		return nil, err
	}
	identity, exists, err := tlsconfig.ClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if exists {
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}

func parseHeaders(values []string) (*connect.Header, error) {
	headers := &connect.Header{}
	for _, value := range values {
		name, content, found := strings.Cut(value, ":")
		if !found || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(content) {
			return nil, fmt.Errorf("%w: --header requires a valid name: value", ErrInvalidFlags)
		}
		switch strings.ToLower(name) {
		case "host", "content-type", "content-length", "transfer-encoding", "content-encoding", "accept-encoding", "connection", "te", "trailer":
			return nil, fmt.Errorf("%w: --header %q is controlled by the RPC transport", ErrInvalidFlags, name)
		}
		if strings.HasPrefix(strings.ToLower(name), "connect-") || strings.HasPrefix(strings.ToLower(name), "grpc-") {
			return nil, fmt.Errorf("%w: --header %q is reserved for the RPC protocol", ErrInvalidFlags, name)
		}
		headers.Add(name, strings.TrimSpace(content))
	}
	return headers, nil
}
