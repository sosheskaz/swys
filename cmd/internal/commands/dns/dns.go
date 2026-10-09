// Package dns constructs direct and system DNS query commands.
package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/dnsquery"
	"github.com/sosheskaz/swys/internal/textdisplay"
)

//go:embed guides
var dnsGuideFiles embed.FS

const (
	dnsCommandName      = "dns"
	dnsQueryShape       = "dns-query"
	dnsResolverSystem   = "system"
	dnsResolverDirect   = "dns"
	dnsTransportUDP     = "udp"
	dnsTransportTCP     = "tcp"
	dnsTransportTLS     = "tls"
	dnsTransportHTTPS   = "https"
	dnsTypeA            = "A"
	dnsTypeAAAA         = "AAAA"
	dnsTypePTR          = "PTR"
	dnsInsecureFlagName = "insecure"
)

type dnsOptions struct {
	resolver   string
	selectMode string
	format     string
	ca         string
	serverName string
	cert       string
	key        string
	timeout    time.Duration
	port       int
	reverse    bool
	systemCA   bool
	insecure   bool
}

type dnsQuery struct {
	endpoint   *dnsquery.Endpoint
	tlsConfig  *tls.Config
	resolver   string
	server     string
	lookup     string
	name       string
	record     string
	transport  string
	selectMode string
	format     string
	timeout    time.Duration
	port       int
	recordType uint16
	portSet    bool
}

type dnsPreparedOutputKey struct{}

type dnsPreparedOutput struct {
	lookupErr error
	data      []byte
}

const (
	dnsFormatText   = "text"
	dnsFormatPlain  = "plain"
	dnsFormatJSON   = "json"
	dnsSelectResult = "result"
	dnsSelectValues = "values"
)

var dnsFormatDescriptions = map[string]string{
	dnsFormatText:  "human-readable text",
	dnsFormatPlain: "plain text without terminal styles",
	dnsFormatJSON:  "structured JSON",
}

// NewCommand constructs DNS commands with the supplied resolver dependencies.
func NewCommand(lifecycle *commandio.Lifecycle, deps dnsquery.Dependencies) *cobra.Command {
	options := &dnsOptions{
		resolver:   dnsResolverSystem,
		selectMode: dnsSelectResult,
		format:     dnsFormatText,
		port:       53,
		timeout:    commandio.DefaultNetworkTimeout,
	}
	command := &cobra.Command{
		Use:     "dns name [type] [@server ...]",
		Aliases: []string{"dig", "nslookup"},
		Short:   "Resolve DNS names and records",
		Long: `Resolve a name through the operating system or query a DNS server directly.

The default system resolver supports A, AAAA, and PTR through net.DefaultResolver;
the exact lookup path depends on the operating system and build. An @server or
explicit --port selects direct DNS. Direct DNS without @server uses configured
nameservers over UDP and retries truncated responses over TCP.

Direct endpoints use @host, @udp://host, @tcp://host, @tls://host, or
@https://host/path. Endpoints may appear anywhere among name and type arguments.
Multiple endpoints are queried in argument order. DNS over TLS and HTTPS verify
certificates by default.`,
		Args: cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return completeDNSArguments(cmd, args, toComplete, options)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			prepared, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			pending, ok := cmd.Context().Value(dnsPreparedOutputKey{}).(dnsPreparedOutput)
			if !ok {
				return commandio.ErrPreparedOutputUnavailable
			}
			if _, err := output.Write(prepared); err != nil {
				return errors.Join(pending.lookupErr, fmt.Errorf("write DNS result: %w", err))
			}
			return pending.lookupErr
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		SupportsOutput: true,
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			queries, err := parseDNSQueries(cmd, args, options)
			if err != nil {
				return nil, err
			}
			prepared, err := prepareDNSOutput(cmd.Context(), queries, deps, presentation.Output(cmd))
			if err != nil {
				return nil, err
			}
			original := cmd.Context()
			cmd.SetContext(context.WithValue(original, dnsPreparedOutputKey{}, prepared))
			return func(err error) error {
				if err != nil {
					cmd.SetContext(original)
					return errors.Join(prepared.lookupErr, err)
				}
				commandio.AppendCleanup(cmd, func() { cmd.SetContext(original) })
				return nil
			}, nil
		},
		Prepare: func(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
			prepared, ok := cmd.Context().Value(dnsPreparedOutputKey{}).(dnsPreparedOutput)
			if !ok {
				return nil, commandio.ErrPreparedOutputUnavailable
			}
			return prepared.data, nil
		},
	})
	commandio.AddShape(command, dnsQueryShape)
	commandio.AddShape(command, "structured-output")
	commandio.AddShape(command, "network")
	flags := command.Flags()
	flags.StringVar(&options.resolver, "resolver", dnsResolverSystem, "resolver mode (system, dns)")
	flags.IntVarP(&options.port, "port", "p", 53, "direct DNS server port")
	flags.BoolVarP(&options.reverse, "reverse", "x", false, "perform a PTR lookup for an IP address")
	flags.DurationVarP(&options.timeout, "timeout", "t", commandio.DefaultNetworkTimeout, "whole lookup timeout (0 disables)")
	flags.StringVar(&options.selectMode, "select", dnsSelectResult, "result selection (result, values)")
	flags.StringVarP(&options.format, commandio.FormatFlagName, "f", dnsFormatText, "result format (text, plain, json)")
	commandio.AddOutputEncodingFlag(command)
	flags.StringVar(&options.cert, tlsconfig.CertFlagName, "", "client certificate chain PEM path")
	flags.StringVarP(&options.key, tlsconfig.KeyFlagName, "k", "", "client private key path")
	flags.StringVar(&options.ca, tlsconfig.CAFlagName, "", "custom CA certificate bundle PEM path")
	flags.BoolVar(&options.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&options.serverName, tlsconfig.ServerNameFlagName, "", "override TLS SNI and verification name")
	flags.BoolVar(&options.insecure, dnsInsecureFlagName, false, "disable TLS certificate and hostname verification")
	if err := command.RegisterFlagCompletionFunc("resolver", func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		values := []string{dnsResolverSystem, dnsResolverDirect}
		if dnsDirectSelectorSupplied(cmd, args) {
			values = []string{dnsResolverDirect}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	commandio.RegisterDescribedFlagCompletion(command, commandio.FormatFlagName,
		func() []string { return []string{dnsFormatText, dnsFormatPlain, dnsFormatJSON} }, dnsFormatDescriptions)
	commandio.RegisterDescribedFlagCompletion(command, "select",
		func() []string { return []string{dnsSelectResult, dnsSelectValues} }, map[string]string{
			dnsSelectResult: "complete DNS result",
			dnsSelectValues: "answer values only",
		})
	tlsconfig.AddArtifactEncodingFlags(command, dnsTLSCompletionAllowed)
	tlsconfig.RegisterArtifactEncodingCompletion(lifecycle,
		func() *cobra.Command { return NewCommand(commandio.NewLifecycle(), deps) }, dnsTLSCompletionAllowed)
	registerDNSContextCompletions(command)
	lifecycle.RegisterCompletion(func(completionCmd *cobra.Command, args []string) {
		prepareDNSCompletion(completionCmd, args, command)
	})
	if err := help.RegisterGuides(command, dnsGuideFiles); err != nil {
		panic(err)
	}
	return command
}

func registerDNSContextCompletions(command *cobra.Command) {
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName} {
		if err := command.RegisterFlagCompletionFunc(name, completeDNSCredentialPath(name)); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{"port", "timeout", tlsconfig.ServerNameFlagName} {
		if err := command.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{dnsInsecureFlagName, tlsconfig.SystemCAFlagName} {
		if err := command.RegisterFlagCompletionFunc(name, completeDNSTrustBoolean(name)); err != nil {
			panic(err)
		}
	}
}

func prepareDNSCompletion(completionCmd *cobra.Command, args []string, command *cobra.Command) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completedArgs := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || actual != command {
		return
	}
	probeRoot := commandio.NewProbeRoot()
	probeRoot.AddCommand(NewCommand(commandio.NewLifecycle(), dnsquery.Dependencies{}))
	probe, probeArgs, err := probeRoot.Find(completedArgs)
	if err != nil || probe.ParseFlags(probeArgs) != nil {
		return
	}
	resolver, err := probe.Flags().GetString("resolver")
	if err != nil {
		return
	}
	if probe.Flags().Changed("resolver") && resolver == dnsResolverSystem {
		command.Flags().Lookup("port").Hidden = true
	}
	for _, name := range []string{
		tlsconfig.CAFlagName, tlsconfig.SystemCAFlagName, tlsconfig.ServerNameFlagName,
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, dnsInsecureFlagName,
	} {
		if !dnsTLSCompletionAllowed(probe, probe.Flags().Args()) || !dnsTrustCompletionAllowed(probe, name) {
			command.Flags().Lookup(name).Hidden = true
		}
	}
}

func dnsTLSCompletionAllowed(command *cobra.Command, args []string) bool {
	resolver, err := command.Flags().GetString("resolver")
	if err != nil || command.Flags().Changed("resolver") && resolver == dnsResolverSystem {
		return false
	}
	servers, _ := splitDNSArguments(args)
	if len(servers) == 0 {
		return len(args) == 0
	}
	for _, server := range servers {
		endpoint, err := dnsquery.ParseEndpoint(strings.TrimPrefix(server, "@"), nil)
		if err != nil || endpoint.Transport != dnsquery.TransportTLS && endpoint.Transport != dnsquery.TransportHTTPS {
			return false
		}
	}
	return true
}

func dnsTrustCompletionAllowed(command *cobra.Command, name string) bool {
	insecure, err := command.Flags().GetBool(dnsInsecureFlagName)
	if err != nil {
		return false
	}
	ca, err := command.Flags().GetString(tlsconfig.CAFlagName)
	if err != nil {
		return false
	}
	systemCA, err := command.Flags().GetBool(tlsconfig.SystemCAFlagName)
	if err != nil {
		return false
	}
	switch name {
	case tlsconfig.CAFlagName, tlsconfig.SystemCAFlagName:
		return !insecure
	case dnsInsecureFlagName:
		return ca == "" && !systemCA
	default:
		return true
	}
}

func completeDNSCredentialPath(name string) cobra.CompletionFunc {
	return func(command *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if !dnsTLSCompletionAllowed(command, args) || !dnsTrustCompletionAllowed(command, name) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}
}

func completeDNSTrustBoolean(name string) cobra.CompletionFunc {
	return func(command *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if !dnsTLSCompletionAllowed(command, args) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var values []string
		for _, candidate := range []bool{true, false} {
			value := strconv.FormatBool(candidate)
			if (!candidate || dnsTrustCompletionAllowed(command, name)) && strings.HasPrefix(value, prefix) {
				values = append(values, value)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeDNSArguments(command *cobra.Command, args []string, toComplete string, options *dnsOptions) ([]string, cobra.ShellCompDirective) {
	_, positional := splitDNSArguments(args)
	if len(positional) != 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	resolver, conflict := dnsCompletionResolver(command, args, options)
	if conflict {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	candidates := []string{dnsTypeA, dnsTypeAAAA, dnsTypePTR}
	if resolver == dnsResolverDirect {
		candidates = directDNSRecordTypes()
	}
	if options.reverse {
		candidates = []string{dnsTypePTR}
	}

	prefix := strings.ToUpper(toComplete)
	completed := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, prefix) {
			completed = append(completed, candidate)
		}
	}
	return completed, cobra.ShellCompDirectiveNoFileComp
}

func dnsCompletionResolver(command *cobra.Command, args []string, options *dnsOptions) (string, bool) {
	directSelected := dnsDirectSelectorSupplied(command, args)
	if options.resolver == dnsResolverSystem && command.Flags().Changed("resolver") && directSelected {
		return "", true
	}
	if options.resolver == dnsResolverDirect || directSelected {
		return dnsResolverDirect, false
	}
	return dnsResolverSystem, false
}

func dnsDirectSelectorSupplied(command *cobra.Command, args []string) bool {
	servers, _ := splitDNSArguments(args)
	return len(servers) > 0 || command.Flags().Changed("port") || dnsTLSOptionsSelected(command)
}

func directDNSRecordTypes() []string {
	types := make([]string, 0, len(dns.StringToType)-2)
	for record, recordType := range dns.StringToType {
		if recordType == dns.TypeAXFR || recordType == dns.TypeIXFR {
			continue
		}
		types = append(types, record)
	}
	sort.Strings(types)
	return types
}

func splitDNSArguments(args []string) ([]string, []string) {
	var servers, positional []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			servers = append(servers, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return servers, positional
}

func parseDNSQueries(cmd *cobra.Command, args []string, options *dnsOptions) ([]dnsQuery, error) {
	servers, positional := splitDNSArguments(args)
	if len(positional) < 1 || len(positional) > 2 {
		return nil, fmt.Errorf("%w: expected name [type] and optional @server arguments", ErrInvalidDNSOptions)
	}
	if len(servers) == 0 {
		servers = []string{""}
	}
	queries := make([]dnsQuery, 0, len(servers))
	for _, server := range servers {
		query, err := parseDNSQuery(cmd, positional, server, options)
		if err != nil {
			return nil, err
		}
		queries = append(queries, query)
	}
	// Load shared credentials only after every endpoint and option is validated.
	var config *tls.Config
	for i := range queries {
		if queries[i].transport != dnsTransportTLS && queries[i].transport != dnsTransportHTTPS {
			continue
		}
		if config == nil {
			var err error
			config, err = encryptedDNSTLSConfig(cmd)
			if err != nil {
				return nil, err
			}
		}
		queries[i].tlsConfig = config
	}
	return queries, nil
}

func parseDNSQuery(cmd *cobra.Command, args []string, server string, options *dnsOptions) (dnsQuery, error) {
	query := dnsQuery{
		resolver: options.resolver, transport: dnsTransportUDP, port: options.port,
		portSet: cmd.Flags().Changed("port"), timeout: options.timeout, selectMode: options.selectMode, format: options.format,
	}
	if server != "" {
		query.server = strings.TrimPrefix(server, "@")
		if query.server == "" {
			return dnsQuery{}, fmt.Errorf("%w: @server must not be empty", ErrInvalidDNSOptions)
		}
		if !strings.Contains(query.server, "://") && strings.ContainsAny(query.server, "/?#@") {
			return dnsQuery{}, fmt.Errorf("%w: invalid bare DNS endpoint %q", ErrInvalidDNSOptions, query.server)
		}
		if err := parseDNSEndpoint(&query); err != nil {
			return dnsQuery{}, err
		}
	}
	query.lookup = args[0]
	query.name = args[0]
	query.record = dnsTypeA
	if len(args) == 2 {
		query.record = strings.ToUpper(args[1])
	}
	if err := applyDNSReverse(&query, args, options.reverse); err != nil {
		return dnsQuery{}, err
	}
	recordType, err := parseDNSRecordType(query.record)
	if err != nil {
		return dnsQuery{}, err
	}
	query.recordType = recordType
	if err := validateDNSQueryOptions(cmd, &query, options); err != nil {
		return dnsQuery{}, err
	}
	return query, nil
}

func applyDNSReverse(query *dnsQuery, args []string, reverse bool) error {
	if !reverse {
		return nil
	}
	if len(args) == 2 && query.record != dnsTypePTR {
		return fmt.Errorf("%w: --reverse requires type PTR when a type is supplied", ErrInvalidDNSOptions)
	}
	address, err := netip.ParseAddr(query.lookup)
	if err != nil {
		return fmt.Errorf("%w: --reverse requires an IP address: %w", ErrInvalidDNSOptions, err)
	}
	query.record = dnsTypePTR
	query.name = dnsutil.ReverseAddr(address.Unmap())
	return nil
}

func parseDNSRecordType(record string) (uint16, error) {
	recordType, ok := dns.StringToType[record]
	if !ok {
		return 0, fmt.Errorf("%w: unknown record type %q", ErrInvalidDNSOptions, record)
	}
	if recordType == dns.TypeAXFR || recordType == dns.TypeIXFR {
		return 0, fmt.Errorf("%w: zone transfer type %s is not supported", ErrInvalidDNSOptions, record)
	}
	return recordType, nil
}

func validateDNSQueryOptions(cmd *cobra.Command, query *dnsQuery, options *dnsOptions) error {
	if err := validateDNSChoiceOptions(options); err != nil {
		return err
	}
	if err := validateDNSLimitOptions(options); err != nil {
		return err
	}
	return selectDNSResolver(cmd, query, options)
}

func validateDNSChoiceOptions(options *dnsOptions) error {
	if options.resolver != dnsResolverSystem && options.resolver != dnsResolverDirect {
		return fmt.Errorf("%w: unknown resolver %q (valid: system, dns)", ErrInvalidDNSOptions, options.resolver)
	}
	if options.format != dnsFormatText && options.format != dnsFormatPlain && options.format != dnsFormatJSON {
		return fmt.Errorf("%w: unknown format %q (valid: text, plain, json)", ErrInvalidDNSOptions, options.format)
	}
	if options.selectMode != dnsSelectResult && options.selectMode != dnsSelectValues {
		return fmt.Errorf("%w: unknown selection %q (valid: result, values)", ErrInvalidDNSOptions, options.selectMode)
	}
	return nil
}

func validateDNSLimitOptions(options *dnsOptions) error {
	if options.port < 1 || options.port > 65535 {
		return fmt.Errorf("%w: port must be from 1 to 65535", ErrInvalidDNSOptions)
	}
	if options.timeout < 0 {
		return fmt.Errorf("%w: timeout must not be negative", ErrInvalidDNSOptions)
	}
	return nil
}

func selectDNSResolver(cmd *cobra.Command, query *dnsQuery, options *dnsOptions) error {
	tlsSelected := dnsTLSOptionsSelected(cmd)
	directSelected := query.server != "" || cmd.Flags().Changed("port") || tlsSelected
	if options.resolver == dnsResolverSystem && cmd.Flags().Changed("resolver") && directSelected {
		return fmt.Errorf("%w: --resolver system conflicts with direct DNS options", ErrInvalidDNSOptions)
	}
	if options.resolver == dnsResolverDirect || directSelected {
		query.resolver = dnsResolverDirect
	}
	if query.resolver == dnsResolverSystem {
		return validateSystemDNSQuery(query)
	}
	return validateDirectDNSOptions(cmd, query, tlsSelected)
}

func validateSystemDNSQuery(query *dnsQuery) error {
	if query.record != dnsTypeA && query.record != dnsTypeAAAA && query.record != dnsTypePTR {
		return fmt.Errorf("%w: %s requires --resolver dns", errUnsupportedSystemType, query.record)
	}
	if query.record != dnsTypePTR {
		return nil
	}
	address, err := netip.ParseAddr(query.lookup)
	if err != nil {
		return fmt.Errorf(
			"%w: system PTR lookup requires an IP address; use --reverse with an IP or --resolver dns for a reverse owner name: %w",
			ErrInvalidDNSOptions,
			err,
		)
	}
	query.name = dnsutil.ReverseAddr(address.Unmap())
	return nil
}

func validateDirectDNSOptions(cmd *cobra.Command, query *dnsQuery, tlsSelected bool) error {
	encrypted := query.transport == dnsTransportTLS || query.transport == dnsTransportHTTPS
	if err := tlsconfig.ValidateArtifactSources(cmd, encrypted, false, ErrInvalidDNSOptions); err != nil {
		return err
	}
	if query.transport == dnsTransportUDP || query.transport == dnsTransportTCP {
		if tlsSelected {
			return fmt.Errorf("%w: TLS options require @tls:// or @https://", ErrInvalidDNSOptions)
		}
		return nil
	}
	return validateEncryptedDNSOptions(cmd)
}

func dnsTLSOptionsSelected(cmd *cobra.Command) bool {
	for _, name := range []string{
		tlsconfig.CAFlagName, "system-ca", tlsconfig.ServerNameFlagName,
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, dnsInsecureFlagName,
		tlsconfig.CAEncodingFlagName, tlsconfig.CertEncodingFlagName, tlsconfig.KeyEncodingFlagName,
	} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

type dnsResult = dnsquery.Result

type dnsSelectedOutput struct {
	result *dnsResult
	values []string
}

func selectDNSResult(result *dnsResult, selection string) dnsSelectedOutput {
	if selection == dnsSelectResult {
		return dnsSelectedOutput{result: result}
	}
	values := make([]string, 0, len(result.Answers))
	for _, answer := range result.Answers {
		values = append(values, answer.Value)
	}
	return dnsSelectedOutput{values: values}
}

func prepareDNSOutput(ctx context.Context, queries []dnsQuery, deps dnsquery.Dependencies, options textdisplay.Options) (dnsPreparedOutput, error) {
	lookupContext, cancel := commandio.NetworkSetupContext(ctx, queries[0].timeout)
	defer cancel()
	results := make([]dnsResult, 0, len(queries))
	var lookupErrors []error
	for i := range queries {
		result, err := resolveDNSQuery(lookupContext, &queries[i], deps)
		if err != nil {
			if len(queries) > 1 {
				err = fmt.Errorf("DNS resolver %s (%s): %w", queries[i].server, queries[i].transport, err)
			}
			lookupErrors = append(lookupErrors, err)
			continue
		}
		results = append(results, result)
	}
	lookupErr := errors.Join(lookupErrors...)
	if len(results) == 0 {
		return dnsPreparedOutput{}, lookupErr
	}
	data, err := renderDNSResults(results, &queries[0], options, len(queries) > 1)
	if err != nil {
		return dnsPreparedOutput{}, errors.Join(lookupErr, err)
	}
	return dnsPreparedOutput{data: data, lookupErr: lookupErr}, nil
}

func resolveDNSQuery(ctx context.Context, query *dnsQuery, deps dnsquery.Dependencies) (dnsResult, error) {
	request := dnsquery.Request{
		Resolver:  dnsquery.Resolver(query.resolver),
		Endpoint:  query.endpoint,
		Lookup:    query.lookup,
		Name:      query.name,
		Type:      query.recordType,
		TLSConfig: query.tlsConfig,
	}
	if query.resolver == dnsResolverDirect && query.endpoint == nil && query.portSet {
		port := uint16(query.port) //nolint:gosec // validateDNSLimitOptions bounds the value.
		request.ConfiguredPort = &port
	}
	result, err := dnsquery.Resolve(ctx, request, deps)
	if err != nil {
		if errors.Is(err, dnsquery.ErrInvalidRequest) || errors.Is(err, dnsquery.ErrInvalidEndpoint) {
			return dnsResult{}, fmt.Errorf("%w: %w", ErrInvalidDNSOptions, err)
		}
		return dnsResult{}, err
	}
	return result, nil
}

func renderDNSResults(results []dnsResult, query *dnsQuery, options textdisplay.Options, multiple bool) ([]byte, error) {
	if query.selectMode == dnsSelectValues {
		values := make([]string, 0, len(results))
		for i := range results {
			values = append(values, selectDNSResult(&results[i], dnsSelectValues).values...)
		}
		return renderDNSResultWithOptions(dnsSelectedOutput{values: values}, query.format, options)
	}
	if !multiple {
		return renderDNSResultWithOptions(selectDNSResult(&results[0], dnsSelectResult), query.format, options)
	}
	if query.format == dnsFormatJSON {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal DNS results: %w", err)
		}
		return append(data, '\n'), nil
	}
	var output bytes.Buffer
	for i := range results {
		data, err := renderDNSResultWithOptions(selectDNSResult(&results[i], dnsSelectResult), query.format, options)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			output.WriteByte('\n')
		}
		output.Write(data)
	}
	return output.Bytes(), nil
}

func renderDNSResult(selected dnsSelectedOutput, format string) ([]byte, error) {
	return renderDNSResultWithOptions(selected, format, textdisplay.Options{})
}

func renderDNSResultWithOptions(selected dnsSelectedOutput, format string, options textdisplay.Options) ([]byte, error) {
	if format == dnsFormatPlain {
		options.Rich = false
	}
	if format == dnsFormatJSON {
		var value any = selected.result
		if selected.result == nil {
			value = selected.values
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal DNS result: %w", err)
		}
		return append(data, '\n'), nil
	}
	var output bytes.Buffer
	printer := textdisplay.New(&output, options)
	if selected.result == nil {
		for _, value := range selected.values {
			printer.Line(value, textdisplay.Normal)
		}
		if output.Len() == 0 {
			return make([]byte, 0), printer.Err()
		}
		return output.Bytes(), printer.Err()
	}
	result := selected.result
	printer.Heading("DNS · " + result.QueryName + " · " + result.QueryType)
	printer.Blank()
	fields := []textdisplay.Field{{Label: "Resolver", Value: string(result.Resolver)}}
	if result.Server == nil {
		fields = append(fields,
			textdisplay.Field{Label: "Server", Value: "unavailable"},
			textdisplay.Field{Label: "Status", Value: "unavailable; DNS packet metadata and TTLs unavailable"},
		)
	} else {
		fields = append(fields,
			textdisplay.Field{Label: "Server", Value: *result.Server + " · " + string(*result.Transport)},
			textdisplay.Field{Label: "Status", Value: *result.Status},
			textdisplay.Field{Label: "ID", Value: strconv.Itoa(int(*result.ID))},
		)
	}
	printer.Fields(fields)
	printer.Section("Answers")
	if len(result.Answers) == 0 {
		printer.Line("    (none)", textdisplay.Muted)
	}
	rows := make([][]string, 0, len(result.Answers))
	for _, answer := range result.Answers {
		ttl := "-"
		if answer.TTL != nil {
			ttl = strconv.FormatUint(uint64(*answer.TTL), 10)
		}
		rows = append(rows, []string{answer.Name, ttl, answer.Class, answer.Type, answer.Value})
	}
	renderDNSAnswers(printer, rows)
	return output.Bytes(), printer.Err()
}

func renderDNSAnswers(printer *textdisplay.Printer, rows [][]string) {
	headers := []string{"Name", "TTL", "Class", "Type", "Value"}
	var table [][]string
	flush := func() {
		if len(table) > 0 {
			printer.Table(headers, table)
			table = nil
		}
	}
	for _, row := range rows {
		table = append(table, row)
		if printer.TableFits(headers, table) {
			continue
		}
		table = table[:len(table)-1]
		flush()
		if printer.TableFits(headers, [][]string{row}) {
			table = [][]string{row}
			continue
		}
		printer.Section(row[3] + " · " + row[0])
		printer.Fields([]textdisplay.Field{
			{Label: "TTL / Class", Value: row[1] + " / " + row[2]},
			{Label: "Value", Value: row[4]},
		})
	}
	flush()
}
