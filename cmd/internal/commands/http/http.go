package http

import (
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
)

//go:embed guides
var httpGuideFiles embed.FS

const (
	httpRequestShape  = "http-request"
	httpCommandName   = "http"
	httpFormatText    = "text"
	httpFormatJSON    = "json"
	httpEncodingRaw   = encoding.Raw
	httpStdinAuto     = "auto"
	httpStdinNever    = "never"
	httpStdinAlways   = "always"
	httpMediaTypeJSON = "application/json"
	httpCodingGzip    = "gzip"
)

type httpOptions struct {
	data           string
	jsonData       string
	stdin          string
	format         string
	inputEncoding  string
	encoding       string
	cert           string
	key            string
	ca             string
	serverName     string
	headers        []string
	forms          []string
	files          []string
	resolves       []string
	requestTimeout time.Duration
	timeout        time.Duration
	maxRedirects   int
	include        bool
	trace          bool
	follow         bool
	fail           bool
	systemCA       bool
	insecure       bool
}

// NewCommand constructs the HTTP command and registers its I/O behavior.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	options := &httpOptions{}
	var prepared *httpPreparedRequest
	command := &cobra.Command{
		Use:   "http URL",
		Short: "Make an HTTP request, optionally tracing its connection",
		Long: `Make an HTTP request and stream its response body.

The method defaults to GET and does not consume stdin. Use --method (-X) to
select a standard or custom HTTP method; method spelling is preserved.
URLs without a scheme default to HTTPS. Use http:// for plain HTTP.
Use --resolve HOST:PORT:ADDRESS[,ADDRESS] to override direct connection
addresses without changing the URL host or TLS identity.
Explicit methods other than GET and HEAD automatically read non-terminal stdin
unless a body option is supplied. Use --stdin never to disable this behavior.
--trace writes diagnostics to stderr; with --format json it adds trace data to
the response envelope, whose body is always a base64 string.
Only gzip is automatically negotiated and decompressed. Supplying any explicit
Accept-Encoding value disables automatic negotiation and decompression.`,
		Args: validateHTTPArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if prepared == nil {
				return cmd.Help()
			}
			return executeHTTPRequest(cmd, options, prepared)
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			prepared = nil
			if len(args) == 0 {
				return func(error) error { return nil }, nil
			}
			request, err := prepareHTTPRequest(cmd, args, options)
			if err != nil {
				return nil, err
			}
			prepared = request
			return func(configureErr error) error {
				if configureErr != nil {
					prepared = nil
					return errors.Join(configureErr, request.body.Close())
				}
				return nil
			}, nil
		},
		SkipIOIf:              func(_ *cobra.Command, args []string) bool { return len(args) == 0 },
		InputPrepared:         true,
		ClearInheritedStreams: true,
	})
	addHTTPCommandShape(command)
	registerHTTPFlags(command, options)
	lifecycle.RegisterCompletion(prepareHTTPCompletion)
	if err := help.RegisterGuides(command, httpGuideFiles); err != nil {
		panic(err)
	}
	return command
}

// RegisterBodyCompletionGroups registers groups that include the root's inherited --input flag.
func RegisterBodyCompletionGroups(command *cobra.Command) {
	command.MarkFlagsMutuallyExclusive("input", "data", httpFormatJSON, "form")
	command.MarkFlagsMutuallyExclusive("input", "data", httpFormatJSON, "file")
}

func addHTTPCommandShape(cmd *cobra.Command) {
	commandio.AddShape(cmd, httpRequestShape)
	commandio.AddShape(cmd, "structured-output")
	commandio.AddShape(cmd, "network")
}

func registerHTTPFlags(cmd *cobra.Command, options *httpOptions) {
	flags := cmd.PersistentFlags()
	flags.StringP("method", "X", http.MethodGet, "HTTP request method")
	mustRegisterHTTPCompletion(cmd, "method", completeHTTPMethod)
	flags.StringArrayVarP(&options.headers, "header", "H", nil, "request header (Name: value); repeatable")
	flags.StringArrayVar(&options.resolves, "resolve", nil, "resolve host:port to numeric address(es); repeatable")
	flags.StringVarP(&options.data, "data", "d", "", "literal raw request body")
	flags.StringVar(&options.jsonData, httpFormatJSON, "", "JSON body: literal JSON, @file, or @- for stdin")
	flags.StringArrayVar(&options.forms, "form", nil, "URL-encoded form field (name=value); repeatable")
	flags.StringArrayVar(&options.files, "file", nil, "multipart file field (name=path); repeatable")
	flags.StringVar(&options.stdin, "stdin", httpStdinAuto, "stdin body selection (auto, never, always)")
	flags.StringVarP(&options.format, commandio.FormatFlagName, "f", httpFormatText, "response format (text, json); JSON bodies are base64")
	flags.StringVarP(&options.encoding, commandio.EncodingFlagName, "e", httpEncodingRaw, "body output encoding ("+strings.Join(encoding.Names(), ", ")+")")
	flags.StringVar(&options.inputEncoding, commandio.InputEncodingFlagName, httpEncodingRaw,
		"raw/JSON body input encoding ("+strings.Join(encoding.Names(), ", ")+")")
	flags.BoolVar(&options.include, "include", false, "include response status and headers before the body")
	flags.BoolVar(&options.trace, "trace", false, "include connection, TLS, and timing diagnostics")
	flags.BoolVar(&options.follow, "follow", true, "follow redirects")
	flags.BoolVar(&options.fail, "fail", true, "return an error for HTTP 4xx/5xx, preserving the response body")
	flags.IntVar(&options.maxRedirects, "max-redirects", 10, "maximum number of redirects to follow")
	flags.DurationVar(&options.timeout, "timeout", commandio.DefaultNetworkTimeout, "connection setup and TLS handshake timeout (0 disables)")
	flags.DurationVar(&options.requestTimeout, "request-timeout", 0, "whole request timeout, including upload and response (0 disables)")
	flags.StringVar(&options.cert, tlsconfig.CertFlagName, "", "client certificate chain PEM path")
	flags.StringVar(&options.key, tlsconfig.KeyFlagName, "", "client private key path")
	flags.StringVar(&options.ca, tlsconfig.CAFlagName, "", "custom CA certificate bundle PEM path")
	flags.BoolVar(&options.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&options.serverName, tlsconfig.ServerNameFlagName, "", "override TLS SNI and verification name")
	flags.BoolVar(&options.insecure, "insecure", false, "disable TLS certificate and hostname verification")
	registerHTTPCompletions(cmd, options)
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName} {
		if err := cmd.MarkPersistentFlagFilename(name); err != nil {
			panic(err)
		}
	}
}

func validateHTTPArgs(cmd *cobra.Command, args []string) error {
	if cmd.Name() == httpCommandName && len(args) == 0 {
		return nil
	}
	_, _, err := httpMethodURL(cmd, args)
	return err
}

func httpMethodURL(cmd *cobra.Command, args []string) (string, *url.URL, error) {
	if len(args) != 1 {
		return "", nil, fmt.Errorf("%w: expected one URL; select a method with --method (-X)", ErrInvalidFlags)
	}
	method, err := cmd.Flags().GetString("method")
	if err != nil {
		return "", nil, fmt.Errorf("read HTTP method: %w", err)
	}
	if !httpToken(method) {
		return "", nil, fmt.Errorf("%w: invalid HTTP method %q", ErrInvalidFlags, method)
	}
	address, err := url.Parse(httpURLWithDefaultScheme(args[0]))
	if err != nil {
		return "", nil, fmt.Errorf("parse HTTP URL: %w", err)
	}
	if (address.Scheme != httpCommandName && address.Scheme != "https") || address.Hostname() == "" {
		return "", nil, fmt.Errorf("%w: URL must use http:// or https:// and include a host", ErrInvalidFlags)
	}
	return method, address, nil
}

func httpURLWithDefaultScheme(address string) string {
	lower := strings.ToLower(address)
	if strings.HasPrefix(lower, "http:/") || strings.HasPrefix(lower, "https:/") {
		return address
	}
	if strings.HasPrefix(address, "//") {
		return "https:" + address
	}
	if schemeEnd := strings.Index(address, "://"); schemeEnd >= 0 && !strings.ContainsAny(address[:schemeEnd], "/?#") {
		return address
	}
	return "https://" + address
}

func httpToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}
