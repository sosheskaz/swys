package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/version"
)

type httpPreparedRequest struct {
	request   *http.Request
	body      *httpBody
	tlsConfig *tls.Config
	resolver  httpResolver
}

func prepareHTTPRequest(cmd *cobra.Command, args []string, options *httpOptions) (*httpPreparedRequest, error) {
	method, address, err := httpMethodURL(cmd, args)
	if err != nil {
		return nil, err
	}
	if err := validateHTTPOptions(cmd, options, method); err != nil {
		return nil, err
	}
	resolver, err := parseHTTPResolves(options.resolves)
	if err != nil {
		return nil, err
	}
	headers, err := parseHTTPHeaders(options.headers)
	if err != nil {
		return nil, err
	}
	if len(options.files) != 0 && headers.Get("Content-Type") != "" {
		return nil, fmt.Errorf("%w: multipart Content-Type is generated with its boundary", errInvalidHTTPFlags)
	}
	config, err := httpTLSConfig(cmd, options)
	if err != nil {
		return nil, err
	}
	body, err := prepareHTTPBody(cmd, options, method)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(cmd.Context(), method, address.String(), body)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create HTTP request: %w", err), body.Close())
	}
	request.GetBody = body.getBody
	request.ContentLength = body.length
	if body.length == 0 {
		request.Body = http.NoBody
	}
	request.Header = headers
	if _, supplied := headers["User-Agent"]; !supplied {
		request.Header.Set("User-Agent", defaultHTTPUserAgent())
	}
	if host := headers.Get("Host"); host != "" {
		request.Host = host
		request.Header.Del("Host")
	}
	if body.contentType != "" && request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", body.contentType)
	}
	return &httpPreparedRequest{request: request, body: body, tlsConfig: config, resolver: resolver}, nil
}

func defaultHTTPUserAgent() string {
	buildVersion := version.Get().Version
	if buildVersion == "" || buildVersion == "(devel)" {
		buildVersion = "dev"
	}
	return "npc/" + buildVersion
}

func validateHTTPOptions(cmd *cobra.Command, options *httpOptions, method string) error {
	if options.timeout < 0 || options.requestTimeout < 0 || options.maxRedirects < 0 {
		return fmt.Errorf("%w: timeouts and --max-redirects cannot be negative", errInvalidHTTPFlags)
	}
	if err := validateHTTPOutputOptions(options, method); err != nil {
		return err
	}
	if err := validateHTTPBodySelection(cmd, options); err != nil {
		return err
	}
	return validateHTTPTLSOptions(cmd, options)
}

func validateHTTPOutputOptions(options *httpOptions, method string) error {
	if options.format != httpFormatText && options.format != httpFormatJSON {
		return fmt.Errorf("%w: --format must be text or json", errInvalidHTTPFlags)
	}
	if _, err := getOutputEncoder(options.encoding); err != nil {
		return err
	}
	if _, err := getInputDecoder(options.inputEncoding); err != nil {
		return err
	}
	if options.encoding != httpEncodingRaw && (options.format == httpFormatJSON || options.include || method == http.MethodHead) {
		return fmt.Errorf("%w: --encoding requires body-only text output", errInvalidHTTPFlags)
	}
	if options.include && options.format == httpFormatJSON {
		return fmt.Errorf("%w: --include is only available with text output", errInvalidHTTPFlags)
	}
	return nil
}

func validateHTTPTLSOptions(cmd *cobra.Command, options *httpOptions) error {
	if (options.cert == "") != (options.key == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", errInvalidHTTPFlags)
	}
	if options.systemCA && options.ca == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", errInvalidHTTPFlags)
	}
	if options.insecure && (options.ca != "" || options.systemCA) {
		return fmt.Errorf("%w: --insecure cannot be combined with trust flags", errInvalidHTTPFlags)
	}
	return validateCertificatePaths(cmd, tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName)
}

func validateHTTPBodySelection(cmd *cobra.Command, options *httpOptions) error {
	sources := 0
	for _, name := range []string{"input", "data", httpFormatJSON} {
		if cmd.Flags().Changed(name) {
			sources++
		}
	}
	hasForm := len(options.forms) != 0 || len(options.files) != 0
	if hasForm {
		sources++
	}
	if sources > 1 {
		return fmt.Errorf("%w: choose one of --input, --data, --json, or form/file fields", errInvalidHTTPFlags)
	}
	if !cmd.Flags().Changed("method") && (sources != 0 || options.stdin == httpStdinAlways) {
		return fmt.Errorf("%w: request bodies require an explicit --method (-X)", errInvalidHTTPFlags)
	}
	if err := validateHTTPStdinSelection(cmd, options, sources); err != nil {
		return err
	}
	if hasForm && options.inputEncoding != httpEncodingRaw {
		return fmt.Errorf("%w: --input-encoding cannot be combined with form/file fields", errInvalidHTTPFlags)
	}
	return validateHTTPBodyPaths(cmd, options)
}

func validateHTTPBodyPaths(cmd *cobra.Command, options *httpOptions) error {
	paths, err := httpBodyPaths(cmd, options)
	if err != nil {
		return err
	}
	output := cmd.Flag("output").Value.String()
	for _, path := range paths {
		if err := rejectSameFile(path, output); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPStdinSelection(cmd *cobra.Command, options *httpOptions, sources int) error {
	if options.stdin != httpStdinAuto && options.stdin != httpStdinNever && options.stdin != httpStdinAlways {
		return fmt.Errorf("%w: --stdin must be auto, never, or always", errInvalidHTTPFlags)
	}
	input := cmd.Flag("input").Value.String()
	if cmd.Flags().Changed("input") && input == "" {
		return fmt.Errorf("%w: --input requires a path or -", errInvalidHTTPFlags)
	}
	explicitStdin := input == "-" || cmd.Flags().Changed(httpFormatJSON) && options.jsonData == "@-"
	if options.stdin == httpStdinNever && explicitStdin || options.stdin == httpStdinAlways && sources > 0 && !explicitStdin {
		return fmt.Errorf("%w: --stdin conflicts with the selected body source", errInvalidHTTPFlags)
	}
	return nil
}

func httpTLSConfig(cmd *cobra.Command, options *httpOptions) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: options.serverName,
	}
	config.InsecureSkipVerify = options.insecure
	if err := addTLSRootCAs(cmd, config); err != nil {
		return nil, err
	}
	identity, exists, err := tlsClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if exists {
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}

func parseHTTPHeaders(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, value := range values {
		name, content, exists := strings.Cut(value, ":")
		if !exists || !httpToken(name) || !httpHeaderValue(content) {
			return nil, fmt.Errorf("%w: invalid header %q", errInvalidHTTPFlags, value)
		}
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
			return nil, fmt.Errorf("%w: %s is determined by the request body", errInvalidHTTPFlags, name)
		}
		headers.Add(name, strings.TrimSpace(content))
	}
	if len(headers.Values("Host")) > 1 {
		return nil, fmt.Errorf("%w: Host may only be specified once", errInvalidHTTPFlags)
	}
	return headers, nil
}

func httpHeaderValue(value string) bool {
	for _, char := range value {
		if char < ' ' && char != '\t' || char == 127 {
			return false
		}
	}
	return true
}
