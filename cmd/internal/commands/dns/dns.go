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
	"github.com/spf13/pflag"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

//go:embed guides
var dnsGuideFiles embed.FS

const (
	dnsCommandName    = "dns"
	dnsQueryShape     = "dns-query"
	dnsResolverSystem = "system"
	dnsResolverDirect = "dns"
	dnsTransportUDP   = "udp"
	dnsTransportTCP   = "tcp"
	dnsTransportTLS   = "tls"
	dnsTransportHTTPS = "https"
	dnsTypeA          = "A"
	dnsTypeAAAA       = "AAAA"
	dnsTypePTR        = "PTR"
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

const (
	dnsFormatText   = "text"
	dnsFormatJSON   = "json"
	dnsSelectResult = "result"
	dnsSelectValues = "values"
)

var dnsFormatDescriptions = map[string]string{
	dnsFormatText: "human-readable text",
	dnsFormatJSON: "structured JSON",
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
		Use:     "dns [@server] name [type]",
		Aliases: []string{"dig", "nslookup"},
		Short:   "Resolve DNS names and records",
		Long: `Resolve a name through the operating system or query a DNS server directly.

The default system resolver supports A, AAAA, and PTR through net.DefaultResolver;
the exact lookup path depends on the operating system and build. An @server or
explicit --port selects direct DNS. Direct DNS without @server uses configured
nameservers over UDP and retries truncated responses over TCP.

Direct endpoints use @host, @udp://host, @tcp://host, @tls://host, or
@https://host/path. DNS over TLS and HTTPS verify certificates by default.`,
		Args: cobra.RangeArgs(1, 3),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return completeDNSArguments(cmd, args, toComplete, options)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			prepared, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			if _, err := output.Write(prepared); err != nil {
				return fmt.Errorf("write DNS result: %w", err)
			}
			return nil
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			query, err := parseDNSQuery(cmd, args, options)
			if err != nil {
				return nil, err
			}
			prepared, err := prepareDNSOutput(cmd.Context(), &query, deps)
			if err != nil {
				return nil, err
			}
			original := cmd.Context()
			cmd.SetContext(context.WithValue(original, dnsPreparedOutputKey{}, prepared))
			return func(err error) error {
				if err != nil {
					cmd.SetContext(original)
					return err
				}
				commandio.AppendCleanup(cmd, func() { cmd.SetContext(original) })
				return nil
			}, nil
		},
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare: func(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
			prepared, ok := cmd.Context().Value(dnsPreparedOutputKey{}).([]byte)
			if !ok {
				return nil, commandio.ErrPreparedOutputUnavailable
			}
			return prepared, nil
		},
	})
	commandio.AddShape(command, dnsQueryShape)
	commandio.AddShape(command, "structured-output")
	commandio.AddShape(command, "network")
	flags := command.Flags()
	flags.Var(&dnsResolverFlagValue{command: command, target: &options.resolver}, "resolver", "resolver mode (system, dns)")
	flags.IntVarP(&options.port, "port", "p", 53, "direct DNS server port")
	flags.BoolVarP(&options.reverse, "reverse", "x", false, "perform a PTR lookup for an IP address")
	flags.DurationVar(&options.timeout, "timeout", commandio.DefaultNetworkTimeout, "whole lookup timeout (0 disables)")
	flags.StringVar(&options.selectMode, "select", dnsSelectResult, "result selection (result, values)")
	flags.StringVarP(&options.format, commandio.FormatFlagName, "f", dnsFormatText, "result format (text, json)")
	commandio.AddOutputEncodingFlag(command)
	flags.StringVar(&options.cert, tlsconfig.CertFlagName, "", "client certificate chain PEM path")
	flags.StringVar(&options.key, tlsconfig.KeyFlagName, "", "client private key path")
	flags.StringVar(&options.ca, tlsconfig.CAFlagName, "", "custom CA certificate bundle PEM path")
	flags.BoolVar(&options.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&options.serverName, tlsconfig.ServerNameFlagName, "", "override TLS SNI and verification name")
	flags.BoolVar(&options.insecure, "insecure", false, "disable TLS certificate and hostname verification")
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
		func() []string { return []string{dnsFormatText, dnsFormatJSON} }, dnsFormatDescriptions)
	commandio.RegisterDescribedFlagCompletion(command, "select",
		func() []string { return []string{dnsSelectResult, dnsSelectValues} }, map[string]string{
			dnsSelectResult: "complete DNS result",
			dnsSelectValues: "answer values only",
		})
	for _, name := range []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName} {
		if err := command.MarkFlagFilename(name); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{"port", "timeout"} {
		if err := command.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions); err != nil {
			panic(err)
		}
	}
	if err := help.RegisterGuides(command, dnsGuideFiles); err != nil {
		panic(err)
	}
	return command
}

type dnsResolverFlagValue struct {
	command *cobra.Command
	target  *string
}

// Set records the resolver value and adjusts only completion-time flag visibility.
func (value *dnsResolverFlagValue) Set(resolver string) error {
	*value.target = resolver
	if dnsCompletionRequested(value.command) {
		for _, name := range []string{
			"port", tlsconfig.CAFlagName, "system-ca", tlsconfig.ServerNameFlagName,
			tlsconfig.CertFlagName, tlsconfig.KeyFlagName, "insecure",
		} {
			if flag := value.command.Flags().Lookup(name); flag != nil {
				flag.Hidden = resolver == dnsResolverSystem
			}
		}
	}
	return nil
}

func (value *dnsResolverFlagValue) String() string {
	return *value.target
}

// Type reports the flag value type shown in command metadata.
func (*dnsResolverFlagValue) Type() string {
	return "string"
}

func dnsCompletionRequested(command *cobra.Command) bool {
	for _, child := range command.Root().Commands() {
		if child.Name() == cobra.ShellCompRequestCmd || child.Name() == cobra.ShellCompNoDescRequestCmd {
			return true
		}
	}
	return false
}

func completeDNSArguments(command *cobra.Command, args []string, toComplete string, options *dnsOptions) ([]string, cobra.ShellCompDirective) {
	position := len(args)
	if len(args) > 0 && strings.HasPrefix(args[0], "@") {
		position--
	}
	if position != 1 {
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
	return len(args) > 0 && strings.HasPrefix(args[0], "@") ||
		command.Flags().Changed("port") || dnsTLSOptionsSelected(command)
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

var _ pflag.Value = (*dnsResolverFlagValue)(nil)

func parseDNSQuery(cmd *cobra.Command, args []string, options *dnsOptions) (dnsQuery, error) {
	query := dnsQuery{
		resolver: options.resolver, transport: dnsTransportUDP, port: options.port,
		portSet: cmd.Flags().Changed("port"), timeout: options.timeout, selectMode: options.selectMode, format: options.format,
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "@") {
		query.server = strings.TrimPrefix(args[0], "@")
		args = args[1:]
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
	if len(args) < 1 || len(args) > 2 {
		return dnsQuery{}, fmt.Errorf("%w: expected [@server] name [type]", ErrInvalidDNSOptions)
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
	if options.format != dnsFormatText && options.format != dnsFormatJSON {
		return fmt.Errorf("%w: unknown format %q (valid: text, json)", ErrInvalidDNSOptions, options.format)
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
	if query.transport == dnsTransportUDP || query.transport == dnsTransportTCP {
		if tlsSelected {
			return fmt.Errorf("%w: TLS options require @tls:// or @https://", ErrInvalidDNSOptions)
		}
		return nil
	}
	if err := validateEncryptedDNSOptions(cmd); err != nil {
		return err
	}
	config, err := encryptedDNSTLSConfig(cmd)
	if err != nil {
		return err
	}
	query.tlsConfig = config
	return nil
}

func dnsTLSOptionsSelected(cmd *cobra.Command) bool {
	for _, name := range []string{tlsconfig.CAFlagName, "system-ca", tlsconfig.ServerNameFlagName, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, "insecure"} {
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

func prepareDNSOutput(ctx context.Context, query *dnsQuery, deps dnsquery.Dependencies) ([]byte, error) {
	lookupContext, cancel := commandio.NetworkSetupContext(ctx, query.timeout)
	defer cancel()
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
	result, err := dnsquery.Resolve(lookupContext, request, deps)
	if err != nil {
		if errors.Is(err, dnsquery.ErrInvalidRequest) || errors.Is(err, dnsquery.ErrInvalidEndpoint) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidDNSOptions, err)
		}
		return nil, err
	}
	return renderDNSResult(selectDNSResult(&result, query.selectMode), query.format)
}

func renderDNSResult(selected dnsSelectedOutput, format string) ([]byte, error) {
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
	if selected.result == nil {
		for _, value := range selected.values {
			fmt.Fprintln(&output, asym.EscapeDiagnosticValue(value))
		}
		if output.Len() == 0 {
			return make([]byte, 0), nil
		}
		return output.Bytes(), nil
	}
	result := selected.result
	fmt.Fprintf(&output, ";; resolver: %s\n", result.Resolver)
	if result.Server == nil {
		fmt.Fprintln(&output, ";; server: unavailable")
		fmt.Fprintln(&output, ";; status: unavailable; DNS packet metadata and TTLs unavailable")
	} else {
		fmt.Fprintf(&output, ";; server: %s (%s)\n", asym.EscapeDiagnosticValue(*result.Server), *result.Transport)
		fmt.Fprintf(&output, ";; status: %s, id: %d\n", *result.Status, *result.ID)
	}
	fmt.Fprintln(&output)
	for _, answer := range result.Answers {
		ttl := "-"
		if answer.TTL != nil {
			ttl = strconv.FormatUint(uint64(*answer.TTL), 10)
		}
		fmt.Fprintf(
			&output,
			"%s\t%s\t%s\t%s\t%s\n",
			asym.EscapeDiagnosticValue(answer.Name),
			ttl,
			answer.Class,
			answer.Type,
			asym.EscapeDiagnosticValue(answer.Value),
		)
	}
	return output.Bytes(), nil
}
