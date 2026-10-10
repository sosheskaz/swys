// Package crpc builds the Connect RPC command.
package crpc

import (
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpguts"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
)

//go:embed guides
var guides embed.FS

// ErrInvalidFlags identifies inconsistent request options before input or output is opened.
var ErrInvalidFlags = errors.New("invalid Connect RPC flags")

const (
	stdinAuto    = "auto"
	stdinNever   = "never"
	stdinAlways  = "always"
	formatJSON   = "json"
	formatJSONL  = "jsonl"
	streamBidi   = "bidi"
	streamServer = "server"
)

type options struct {
	stream                        string
	data, stdin, format           string
	ca, cert, key, serverName     string
	headers, resolves             []string
	connectTimeout, timeout, wait time.Duration
	maxMessageSize                int
	systemCA, insecure, verbose   bool
}

// NewCommand constructs Connect RPC invocation and registers its I/O lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	settings := &options{}
	var pending *preparation
	command := &cobra.Command{
		Use:               "crpc URL [SERVICE/METHOD]",
		Aliases:           []string{"connectrpc"},
		Short:             "Call Connect RPC services with JSON",
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pending == nil {
				return commandio.ErrPreparedOutputUnavailable
			}
			return errors.Join(pending.run(cmd.OutOrStdout()), pending.close())
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		SupportsInput: true, SupportsOutput: true,
		InputPrepared: true, ClearInheritedStreams: true,
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			pending = nil
			result, err := prepare(cmd, args, settings)
			if err != nil {
				return nil, err
			}
			pending = result
			return func(err error) error {
				if err != nil {
					pending = nil
					return errors.Join(err, result.close())
				}
				commandio.AppendCleanup(cmd, func() {
					_ = result.close() //nolint:errcheck // RunE or the configure error path already reports closure failures
					pending = nil
				})
				return nil
			}, nil
		},
	})
	commandio.AddShape(command, "structured-output")
	commandio.AddShape(command, "crpc-request")
	commandio.AddShape(command, "network")
	commandio.AddInputEncodingFlag(command)
	commandio.AddOutputEncodingFlag(command)
	flags := command.Flags()
	flags.StringVar(&settings.stream, "stream", "", "RPC mode: unary, server, client, or bidi (default unary)")
	flags.DurationVarP(&settings.wait, "wait", "w", 0, "response drain timeout after sending ends (0 disables)")
	flags.StringVarP(&settings.data, "data", "d", "", "literal JSON request")
	flags.StringVar(&settings.stdin, "stdin", stdinAuto, "read stdin: auto (non-terminal), never, or always")
	flags.StringVarP(&settings.format, "format", "f", "", "response format (json or jsonl); streams default to jsonl")
	flags.StringArrayVarP(&settings.headers, "header", "H", nil, "request header (name: value); repeatable")
	flags.StringArrayVar(&settings.resolves, "resolve", nil, "override HOST:PORT with ADDRESS[,ADDRESS]; repeatable")
	flags.DurationVarP(&settings.connectTimeout, "connect-timeout", "c", commandio.DefaultNetworkTimeout, "connection and TLS setup timeout (0 disables)")
	flags.DurationVarP(&settings.timeout, "timeout", "t", 0, "whole RPC timeout; includes streaming input pauses (0 disables)")
	flags.IntVar(&settings.maxMessageSize, "max-message-size", 16<<20, "maximum uncompressed JSON bytes per sent or received message")
	flags.StringVar(&settings.ca, "ca", "", "custom CA certificate bundle path; - reads stdin")
	flags.BoolVar(&settings.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&settings.cert, "cert", "", "client certificate chain path; - reads stdin")
	flags.StringVarP(&settings.key, "key", "k", "", "client private key path; - reads stdin")
	flags.StringVar(&settings.serverName, "servername", "", "override TLS SNI and verification name")
	flags.BoolVar(&settings.insecure, "insecure", false, "disable TLS certificate and hostname verification")
	flags.BoolVarP(&settings.verbose, "verbose", "v", false, "write status, response headers, and TLS details to stderr")
	commandio.RegisterFlagCompletion(command, "stdin", func() []string { return []string{stdinAuto, stdinNever, stdinAlways} })
	commandio.RegisterFlagCompletion(command, "format", func() []string { return []string{formatJSON, formatJSONL} })
	commandio.RegisterFlagCompletion(command, "stream", func() []string { return []string{"unary", streamServer, "client", streamBidi} })
	for _, name := range []string{"connect-timeout", "timeout", "wait"} {
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

func streamType(value string) (connect.StreamType, error) {
	switch value {
	case "", "unary":
		return connect.StreamTypeUnary, nil
	case streamServer:
		return connect.StreamTypeServer, nil
	case "client":
		return connect.StreamTypeClient, nil
	case streamBidi:
		return connect.StreamTypeBidi, nil
	default:
		return 0, fmt.Errorf("%w: --stream must be unary, server, client, or bidi", ErrInvalidFlags)
	}
}

func validate(cmd *cobra.Command, settings *options, secure bool) error {
	if settings.connectTimeout < 0 || settings.timeout < 0 || settings.wait < 0 || settings.maxMessageSize <= 0 {
		return fmt.Errorf("%w: timeouts must be non-negative and --max-message-size must be positive", ErrInvalidFlags)
	}
	if settings.format != "" && settings.format != formatJSON && settings.format != formatJSONL {
		return fmt.Errorf("%w: --format must be json or jsonl", ErrInvalidFlags)
	}
	if settings.format == formatJSON && (settings.stream == streamServer || settings.stream == streamBidi) {
		return fmt.Errorf("%w: multiple-response streams require --format jsonl", ErrInvalidFlags)
	}
	if err := validateRequestSources(cmd, settings); err != nil {
		return err
	}
	return validateTLS(cmd, settings, secure)
}

func validateRequestSources(cmd *cobra.Command, settings *options) error {
	if settings.stdin != stdinAuto && settings.stdin != stdinNever && settings.stdin != stdinAlways {
		return fmt.Errorf("%w: --stdin must be auto, never, or always", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("data") && cmd.Flags().Changed("input") {
		return fmt.Errorf("%w: --data and --input are mutually exclusive", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("stdin") && settings.stdin != stdinAuto && (cmd.Flags().Changed("data") || cmd.Flags().Changed("input")) {
		return fmt.Errorf("%w: --stdin cannot accompany --data or --input", ErrInvalidFlags)
	}
	return nil
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
