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
	flagInput             = "input"
	flagStdin             = "stdin"
	flagProtoset          = "protoset"
	flagTemplate          = "template"
	flagStream            = "stream"
	flagCA                = "ca"
	flagCert              = "cert"
	flagKey               = "key"
	flagSystemCA          = "system-ca"
	flagServerName        = "servername"
	flagReflect           = "reflect"
	flagReflectionTimeout = "reflection-timeout"
	flagHeader            = "header"
	flagInsecure          = "insecure"
	flagInputEncoding     = "input-encoding"
	flagList              = "list"
	flagWait              = "wait"
	flagMaxMessageSize    = "max-message-size"
	flagData              = "data"
	flagDescribe          = "describe"
	flagTimeout           = "timeout"
	stdinAuto             = "auto"
	stdinNever            = "never"
	stdinAlways           = "always"
	formatJSON            = "json"
	formatJSONL           = "jsonl"
	streamBidi            = "bidi"
	streamUnary           = "unary"
	streamClient          = "client"
	streamServer          = "server"
)

type options struct {
	stream, protoset, list, describe, template            string
	data, stdin, format                                   string
	ca, cert, key, serverName                             string
	headers, resolves                                     []string
	connectTimeout, timeout, wait, reflectionTimeout      time.Duration
	maxMessageSize                                        int
	systemCA, insecure, verbose, reflectSchema, discovery bool
}

// NewCommand constructs Connect RPC invocation and registers its I/O lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	settings := &options{}
	var pending *preparation
	command := &cobra.Command{
		Use:               "crpc [URL] [SERVICE/METHOD]",
		Aliases:           []string{"connectrpc"},
		Short:             "Call Connect RPC services with JSON",
		Args:              cobra.MaximumNArgs(2),
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
	flags.StringVar(&settings.protoset, flagProtoset, "", "binary protobuf FileDescriptorSet path")
	flags.BoolVar(&settings.reflectSchema, flagReflect, false, "use server reflection to validate the method and request")
	flags.DurationVar(&settings.reflectionTimeout, flagReflectionTimeout, commandio.DefaultNetworkTimeout, "whole reflection lookup timeout (0 disables)")
	flags.StringVar(&settings.list, flagList, "", "list methods of a service")
	flags.StringVar(&settings.describe, flagDescribe, "", "describe a protobuf symbol")
	flags.StringVar(&settings.template, flagTemplate, "", "print an editable JSON request for SERVICE/METHOD")
	flags.StringVar(&settings.stream, flagStream, "", "RPC mode: unary, server, client, or bidi (default unary)")
	flags.DurationVarP(&settings.wait, flagWait, "w", 0, "response drain timeout after sending ends (0 disables)")
	flags.StringVarP(&settings.data, flagData, "d", "", "literal JSON request")
	flags.StringVar(&settings.stdin, flagStdin, stdinAuto, "read stdin: auto (non-terminal), never, or always")
	flags.StringVarP(&settings.format, "format", "f", "", "format: json/jsonl for calls; text/plain/json for discovery")
	flags.StringArrayVarP(&settings.headers, flagHeader, "H", nil, "request header (name: value); repeatable")
	flags.StringArrayVar(&settings.resolves, "resolve", nil, "override HOST:PORT with ADDRESS[,ADDRESS]; repeatable")
	flags.DurationVarP(&settings.connectTimeout, "connect-timeout", "c", commandio.DefaultNetworkTimeout, "connection and TLS setup timeout (0 disables)")
	flags.DurationVarP(&settings.timeout, flagTimeout, "t", 0, "whole RPC timeout; includes streaming input pauses (0 disables)")
	flags.IntVar(&settings.maxMessageSize, flagMaxMessageSize, 16<<20, "maximum uncompressed JSON bytes per sent or received message")
	flags.StringVar(&settings.ca, flagCA, "", "custom CA certificate bundle path; - reads stdin")
	flags.BoolVar(&settings.systemCA, flagSystemCA, false, "include system roots with --ca")
	flags.StringVar(&settings.cert, flagCert, "", "client certificate chain path; - reads stdin")
	flags.StringVarP(&settings.key, flagKey, "k", "", "client private key path; - reads stdin")
	flags.StringVar(&settings.serverName, flagServerName, "", "override TLS SNI and verification name")
	flags.BoolVar(&settings.insecure, flagInsecure, false, "disable TLS certificate and hostname verification")
	flags.BoolVarP(&settings.verbose, "verbose", "v", false, "write status, response headers, and TLS details to stderr")
	commandio.RegisterFlagCompletion(command, flagStdin, func() []string { return []string{stdinAuto, stdinNever, stdinAlways} })
	for _, name := range []string{"connect-timeout", flagTimeout, flagWait, flagReflectionTimeout} {
		commandio.RegisterDurationCompletion(command, name, "Disable this timeout", commandio.NetworkCompletion{})
	}
	for _, name := range []string{flagCA, flagCert, flagKey, flagProtoset} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	tlsconfig.AddArtifactEncodingFlags(command, tlsApplicable)
	tlsconfig.RegisterArtifactEncodingCompletion(lifecycle, func() *cobra.Command { return NewCommand(commandio.NewLifecycle()) }, tlsApplicable)
	registerCompletion(command, settings, lifecycle)
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
	case "", streamUnary:
		return connect.StreamTypeUnary, nil
	case streamServer:
		return connect.StreamTypeServer, nil
	case streamClient:
		return connect.StreamTypeClient, nil
	case streamBidi:
		return connect.StreamTypeBidi, nil
	default:
		return 0, fmt.Errorf("%w: --stream must be unary, server, client, or bidi", ErrInvalidFlags)
	}
}

func validate(cmd *cobra.Command, settings *options, secure bool) error {
	if settings.connectTimeout < 0 || settings.timeout < 0 || settings.wait < 0 || settings.reflectionTimeout < 0 || settings.maxMessageSize <= 0 {
		return fmt.Errorf("%w: timeouts must be non-negative and --max-message-size must be positive", ErrInvalidFlags)
	}
	if err := validateSchemaOptions(cmd, settings); err != nil {
		return err
	}
	if err := validateFormat(settings); err != nil {
		return err
	}
	if err := validateRequestSources(cmd, settings); err != nil {
		return err
	}
	return validateTLS(cmd, settings, secure)
}

func validateFormat(settings *options) error {
	if settings.discovery && settings.template == "" {
		if settings.format != "" && settings.format != "text" && settings.format != "plain" && settings.format != formatJSON {
			return fmt.Errorf("%w: discovery format must be text, plain, or json", ErrInvalidFlags)
		}
	} else if settings.format != "" && settings.format != formatJSON && settings.format != formatJSONL {
		return fmt.Errorf("%w: call format must be json or jsonl", ErrInvalidFlags)
	}
	return nil
}

func validateRequestSources(cmd *cobra.Command, settings *options) error {
	if settings.stdin != stdinAuto && settings.stdin != stdinNever && settings.stdin != stdinAlways {
		return fmt.Errorf("%w: --stdin must be auto, never, or always", ErrInvalidFlags)
	}
	if cmd.Flags().Changed(flagData) && cmd.Flags().Changed(flagInput) {
		return fmt.Errorf("%w: --data and --input are mutually exclusive", ErrInvalidFlags)
	}
	if cmd.Flags().Changed(flagStdin) && settings.stdin != stdinAuto && (cmd.Flags().Changed(flagData) || cmd.Flags().Changed(flagInput)) {
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
		for _, name := range []string{flagCA, flagSystemCA, flagCert, flagKey, flagServerName, flagInsecure} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("%w: --%s requires HTTPS", ErrInvalidFlags, name)
			}
		}
	}
	if err := tlsconfig.ValidateArtifactSources(cmd, secure, usesStdin(cmd, settings), ErrInvalidFlags); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, flagCA, flagCert, flagKey, flagProtoset)
}

func usesStdin(cmd *cobra.Command, settings *options) bool {
	if settings.discovery {
		return false
	}
	if cmd.Flags().Changed(flagInput) {
		return cmd.Flag(flagInput).Value.String() == "-"
	}
	if cmd.Flags().Changed(flagData) {
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
