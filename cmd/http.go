package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	httpRequestShape  = "http-request"
	httpCommandName   = "http"
	httpFormatText    = "text"
	httpFormatJSON    = "json"
	httpEncodingRaw   = byteEncodingRaw
	httpStdinAuto     = "auto"
	httpStdinNever    = "never"
	httpStdinAlways   = "always"
	httpMediaTypeJSON = "application/json"
	httpCodingGzip    = "gzip"
	httpCodingBrotli  = "br"
	httpCodingZstd    = "zstd"
)

var (
	errInvalidHTTPFlags   = errors.New("invalid HTTP options")
	errInvalidHTTPResolve = errors.New("invalid HTTP resolve rule")
	errHTTPStatus         = errors.New("HTTP response status indicates failure")
	errHTTPRedirect       = errors.New("HTTP redirect could not be followed")
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

func newHTTPCmd() *cobra.Command {
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
HTTP header completion suggests common values only. Selecting deflate for
Accept-Encoding requests an encoding npc does not decode; any explicit
Accept-Encoding disables automatic negotiation and decompression.`,
		Args: validateHTTPArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if prepared == nil {
				return cmd.Help()
			}
			return executeHTTPRequest(cmd, options, prepared)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			prepared = nil
			if cmd.Name() == httpCommandName && len(args) == 0 {
				return nil
			}
			request, err := prepareHTTPRequest(cmd, args, options)
			if err != nil {
				return err
			}
			if err := configureCommandIO(cmd); err != nil {
				return errors.Join(err, request.body.Close())
			}
			prepared = request
			return nil
		},
	}
	addHTTPCommandShape(command)
	registerHTTPFlags(command, options)
	return command
}

func registerHTTPBodyCompletionGroups(command *cobra.Command) {
	command.MarkFlagsMutuallyExclusive("input", "data", httpFormatJSON, "form")
	command.MarkFlagsMutuallyExclusive("input", "data", httpFormatJSON, "file")
}

func addHTTPCommandShape(cmd *cobra.Command) {
	addCommandShape(cmd, httpRequestShape)
	addCommandShape(cmd, structuredOutputShape)
	addCommandShape(cmd, networkShape)
}

func registerHTTPFlags(cmd *cobra.Command, options *httpOptions) {
	flags := cmd.PersistentFlags()
	flags.StringP("method", "X", http.MethodGet, "HTTP request method")
	mustRegisterHTTPCompletion(cmd, "method", completeHTTPMethod)
	flags.StringArrayVarP(&options.headers, "header", "H", nil, "request header (Name: value); repeatable")
	flags.StringArrayVar(&options.resolves, "resolve", nil, "resolve host:port to numeric address(es); repeatable")
	flags.StringVar(&options.data, "data", "", "literal raw request body")
	flags.StringVar(&options.jsonData, httpFormatJSON, "", "JSON body: literal JSON, @file, or @- for stdin")
	flags.StringArrayVar(&options.forms, "form", nil, "URL-encoded form field (name=value); repeatable")
	flags.StringArrayVar(&options.files, "file", nil, "multipart file field (name=path); repeatable")
	flags.StringVar(&options.stdin, "stdin", httpStdinAuto, "stdin body selection (auto, never, always)")
	flags.StringVarP(&options.format, formatFlagName, "f", httpFormatText, "response format (text, json); JSON bodies are base64")
	flags.StringVarP(&options.encoding, encodingFlagName, "e", httpEncodingRaw, "body output encoding ("+strings.Join(byteEncodingNames(), ", ")+")")
	flags.StringVar(&options.inputEncoding, inputEncodingFlagName, httpEncodingRaw, "raw/JSON body input encoding ("+strings.Join(byteEncodingNames(), ", ")+")")
	flags.BoolVar(&options.include, "include", false, "include response status and headers before the body")
	flags.BoolVar(&options.trace, "trace", false, "include connection, TLS, and timing diagnostics")
	flags.BoolVar(&options.follow, "follow", true, "follow redirects")
	flags.BoolVar(&options.fail, "fail", true, "return an error for HTTP 4xx/5xx, preserving the response body")
	flags.IntVar(&options.maxRedirects, "max-redirects", 10, "maximum number of redirects to follow")
	flags.DurationVar(&options.timeout, "timeout", defaultNetworkTimeout, "connection setup and TLS handshake timeout (0 disables)")
	flags.DurationVar(&options.requestTimeout, "request-timeout", 0, "whole request timeout, including upload and response (0 disables)")
	flags.StringVar(&options.cert, tlsCertFlagName, "", "client certificate chain PEM path")
	flags.StringVar(&options.key, tlsKeyFlagName, "", "client private key path")
	flags.StringVar(&options.ca, tlsCAFlagName, "", "custom CA certificate bundle PEM path")
	flags.BoolVar(&options.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&options.serverName, "servername", "", "override TLS SNI and verification name")
	flags.BoolVar(&options.insecure, "insecure", false, "disable TLS certificate and hostname verification")
	registerHTTPCompletions(cmd, options)
	for _, name := range []string{tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName} {
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
		return "", nil, fmt.Errorf("%w: expected one URL; select a method with --method (-X)", errInvalidHTTPFlags)
	}
	method, err := cmd.Flags().GetString("method")
	if err != nil {
		return "", nil, fmt.Errorf("read HTTP method: %w", err)
	}
	if !httpToken(method) {
		return "", nil, fmt.Errorf("%w: invalid HTTP method %q", errInvalidHTTPFlags, method)
	}
	address, err := url.Parse(httpURLWithDefaultScheme(args[0]))
	if err != nil {
		return "", nil, fmt.Errorf("parse HTTP URL: %w", err)
	}
	if (address.Scheme != httpCommandName && address.Scheme != "https") || address.Hostname() == "" {
		return "", nil, fmt.Errorf("%w: URL must use http:// or https:// and include a host", errInvalidHTTPFlags)
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
