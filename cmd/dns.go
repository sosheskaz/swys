package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

const (
	dnsCommandName    = "dns"
	dnsQueryShape     = "dns-query"
	dnsResolverSystem = "system"
	dnsResolverDirect = "dns"
	dnsTransportUDP   = "udp"
	dnsTransportTCP   = "tcp"
	dnsFormatText     = "text"
	dnsFormatJSON     = "json"
	dnsTypeA          = "A"
	dnsTypeAAAA       = "AAAA"
	dnsTypePTR        = "PTR"
)

var (
	errInvalidDNSOptions      = errors.New("invalid DNS options")
	errUnsupportedSystemType  = errors.New("record type is unavailable from the system resolver")
	errDNSResponseMismatch    = errors.New("DNS response does not match query")
	errNoConfiguredDNSServer  = errors.New("no configured DNS servers found")
	errDNSResolverUnavailable = errors.New("DNS resolver is unavailable")
)

type dnsSystemResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

type dnsExchangeFunc func(context.Context, *dns.Msg, string, string) (*dns.Msg, error)

type dnsDependencies struct {
	system            dnsSystemResolver
	exchange          dnsExchangeFunc
	configuredServers func() ([]string, error)
}

func defaultDNSDependencies() dnsDependencies {
	return dnsDependencies{
		system:            net.DefaultResolver,
		exchange:          exchangeDNS,
		configuredServers: configuredDNSServers,
	}
}

type dnsOptions struct {
	resolver  string
	transport string
	format    string
	port      int
	timeout   time.Duration
	short     bool
	reverse   bool
}

type dnsQuery struct {
	resolver   string
	server     string
	lookup     string
	name       string
	record     string
	transport  string
	format     string
	timeout    time.Duration
	port       int
	portSet    bool
	recordType uint16
	short      bool
}

type dnsPreparedOutputKey struct{}

func newDNSCmd(deps dnsDependencies) *cobra.Command {
	options := &dnsOptions{
		resolver:  dnsResolverSystem,
		transport: dnsTransportUDP,
		format:    dnsFormatText,
		port:      53,
		timeout:   defaultNetworkTimeout,
	}
	command := &cobra.Command{
		Use:     "dns [@server] name [type]",
		Aliases: []string{"dig", "nslookup"},
		Short:   "Resolve DNS names and records",
		Long: `Resolve a name through the operating system or query a DNS server directly.

The default system resolver supports A, AAAA, and PTR through net.DefaultResolver;
the exact lookup path depends on the operating system and build. An @server,
explicit --transport, or explicit --port selects direct DNS. Direct DNS without
@server uses configured nameservers and retries truncated UDP responses over TCP.`,
		Args: cobra.RangeArgs(1, 3),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return completeDNSArguments(cmd, args, toComplete, options)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			prepared, output, err := takePreparedOutput(cmd)
			if err != nil {
				return err
			}
			if _, err := output.Write(prepared); err != nil {
				return fmt.Errorf("write DNS result: %w", err)
			}
			return nil
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			query, err := parseDNSQuery(cmd, args, options)
			if err != nil {
				return err
			}
			prepared, err := prepareDNSOutput(cmd.Context(), &query, deps)
			if err != nil {
				return err
			}
			original := cmd.Context()
			cmd.SetContext(context.WithValue(original, dnsPreparedOutputKey{}, prepared))
			if err := configureCommandIO(cmd); err != nil {
				cmd.SetContext(original)
				return err
			}
			state, ok := cmd.Context().Value(commandIOKey{}).(*commandIO)
			if !ok {
				cmd.SetContext(original)
				return errPreparedOutputUnavailable
			}
			cleanup := state.cleanup
			state.cleanup = func() error {
				defer cmd.SetContext(original)
				return cleanup()
			}
			return nil
		},
	}
	addCommandShape(command, dnsQueryShape)
	addCommandShape(command, structuredOutputShape)
	addCommandShape(command, networkShape)
	flags := command.Flags()
	flags.Var(&dnsResolverFlagValue{command: command, target: &options.resolver}, "resolver", "resolver mode (system, dns)")
	flags.StringVar(&options.transport, "transport", dnsTransportUDP, "direct DNS transport (udp, tcp)")
	flags.IntVarP(&options.port, "port", "p", 53, "direct DNS server port")
	flags.BoolVarP(&options.reverse, "reverse", "x", false, "perform a PTR lookup for an IP address")
	flags.DurationVar(&options.timeout, "timeout", defaultNetworkTimeout, "whole lookup timeout (0 disables)")
	flags.BoolVar(&options.short, "short", false, "print only answer values")
	flags.StringVarP(&options.format, formatFlagName, "f", dnsFormatText, "result format (text, json)")
	if err := command.RegisterFlagCompletionFunc("resolver", func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		values := []string{dnsResolverSystem, dnsResolverDirect}
		if dnsDirectSelectorSupplied(cmd, args) {
			values = []string{dnsResolverDirect}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	registerFlagCompletion(command, "transport", func() []string {
		if command.Flags().Changed("resolver") && options.resolver == dnsResolverSystem {
			return nil
		}
		return []string{dnsTransportUDP, dnsTransportTCP}
	})
	registerFlagCompletion(command, formatFlagName, func() []string { return []string{dnsFormatText, dnsFormatJSON} })
	for _, name := range []string{"port", "timeout"} {
		if err := command.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions); err != nil {
			panic(err)
		}
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
		value.command.Flags().Lookup("transport").Hidden = resolver == dnsResolverSystem
		value.command.Flags().Lookup("port").Hidden = resolver == dnsResolverSystem
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
		command.Flags().Changed("transport") || command.Flags().Changed("port")
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
		resolver: options.resolver, transport: options.transport, port: options.port,
		portSet: cmd.Flags().Changed("port"), timeout: options.timeout, format: options.format, short: options.short,
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "@") {
		query.server = strings.TrimPrefix(args[0], "@")
		args = args[1:]
		if query.server == "" {
			return dnsQuery{}, fmt.Errorf("%w: @server must not be empty", errInvalidDNSOptions)
		}
	}
	if len(args) < 1 || len(args) > 2 {
		return dnsQuery{}, fmt.Errorf("%w: expected [@server] name [type]", errInvalidDNSOptions)
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
		return fmt.Errorf("%w: --reverse requires type PTR when a type is supplied", errInvalidDNSOptions)
	}
	address, err := netip.ParseAddr(query.lookup)
	if err != nil {
		return fmt.Errorf("%w: --reverse requires an IP address: %w", errInvalidDNSOptions, err)
	}
	query.record = dnsTypePTR
	query.name = dnsutil.ReverseAddr(address.Unmap())
	return nil
}

func parseDNSRecordType(record string) (uint16, error) {
	recordType, ok := dns.StringToType[record]
	if !ok {
		return 0, fmt.Errorf("%w: unknown record type %q", errInvalidDNSOptions, record)
	}
	if recordType == dns.TypeAXFR || recordType == dns.TypeIXFR {
		return 0, fmt.Errorf("%w: zone transfer type %s is not supported", errInvalidDNSOptions, record)
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
	if options.transport != dnsTransportUDP && options.transport != dnsTransportTCP {
		return fmt.Errorf("%w: unknown transport %q (valid: udp, tcp)", errInvalidDNSOptions, options.transport)
	}
	if options.resolver != dnsResolverSystem && options.resolver != dnsResolverDirect {
		return fmt.Errorf("%w: unknown resolver %q (valid: system, dns)", errInvalidDNSOptions, options.resolver)
	}
	if options.format != dnsFormatText && options.format != dnsFormatJSON {
		return fmt.Errorf("%w: unknown format %q (valid: text, json)", errInvalidDNSOptions, options.format)
	}
	return nil
}

func validateDNSLimitOptions(options *dnsOptions) error {
	if options.port < 1 || options.port > 65535 {
		return fmt.Errorf("%w: port must be from 1 to 65535", errInvalidDNSOptions)
	}
	if options.timeout < 0 {
		return fmt.Errorf("%w: timeout must not be negative", errInvalidDNSOptions)
	}
	return nil
}

func selectDNSResolver(cmd *cobra.Command, query *dnsQuery, options *dnsOptions) error {
	directSelected := query.server != "" || cmd.Flags().Changed("transport") || cmd.Flags().Changed("port")
	if options.resolver == dnsResolverSystem && cmd.Flags().Changed("resolver") && directSelected {
		return fmt.Errorf("%w: --resolver system conflicts with @server, --transport, or --port", errInvalidDNSOptions)
	}
	if options.resolver == dnsResolverDirect || directSelected {
		query.resolver = dnsResolverDirect
	}
	if query.resolver == dnsResolverSystem && query.record != dnsTypeA && query.record != dnsTypeAAAA && query.record != dnsTypePTR {
		return fmt.Errorf("%w: %s requires --resolver dns", errUnsupportedSystemType, query.record)
	}
	if query.resolver == dnsResolverSystem && query.record == dnsTypePTR {
		address, err := netip.ParseAddr(query.lookup)
		if err != nil {
			return fmt.Errorf(
				"%w: system PTR lookup requires an IP address; use --reverse with an IP or --resolver dns for a reverse owner name: %w",
				errInvalidDNSOptions,
				err,
			)
		}
		query.name = dnsutil.ReverseAddr(address.Unmap())
	}
	return nil
}

type dnsAnswer struct {
	Name  string  `json:"name"`
	Type  string  `json:"type"`
	Class string  `json:"class"`
	TTL   *uint32 `json:"ttl"`
	Value string  `json:"value"`
}

type dnsResult struct {
	Resolver           string      `json:"resolver"`
	Server             *string     `json:"server"`
	Transport          *string     `json:"transport"`
	QueryName          string      `json:"query_name"`
	QueryType          string      `json:"query_type"`
	Status             *string     `json:"status"`
	ID                 *uint16     `json:"id"`
	Authoritative      *bool       `json:"authoritative"`
	Truncated          *bool       `json:"truncated"`
	RecursionAvailable *bool       `json:"recursion_available"`
	Answers            []dnsAnswer `json:"answers"`
}

func prepareDNSOutput(ctx context.Context, query *dnsQuery, deps dnsDependencies) ([]byte, error) {
	lookupContext, cancel := networkSetupContext(ctx, query.timeout)
	defer cancel()
	var (
		result dnsResult
		err    error
	)
	if query.resolver == dnsResolverSystem {
		if deps.system == nil {
			return nil, fmt.Errorf("%w: system", errDNSResolverUnavailable)
		}
		result, err = resolveSystemDNS(lookupContext, query, deps.system)
	} else {
		if deps.exchange == nil || deps.configuredServers == nil {
			return nil, fmt.Errorf("%w: direct", errDNSResolverUnavailable)
		}
		result, err = resolveDirectDNS(lookupContext, query, deps)
	}
	if err != nil {
		return nil, err
	}
	return renderDNSResult(&result, query.format, query.short)
}

func resolveSystemDNS(ctx context.Context, query *dnsQuery, resolver dnsSystemResolver) (dnsResult, error) {
	result := dnsResult{Resolver: dnsResolverSystem, QueryName: dnsutil.Fqdn(query.name), QueryType: query.record, Answers: []dnsAnswer{}}
	switch query.record {
	case dnsTypeA, dnsTypeAAAA:
		network := "ip4"
		if query.record == dnsTypeAAAA {
			network = "ip6"
		}
		addresses, err := resolver.LookupNetIP(ctx, network, query.lookup)
		if err != nil {
			return dnsResult{}, fmt.Errorf("system %s lookup for %q: %w", query.record, query.lookup, err)
		}
		for _, address := range addresses {
			result.Answers = append(result.Answers, dnsAnswer{Name: dnsutil.Fqdn(query.lookup), Type: query.record, Class: "IN", Value: address.String()})
		}
	case dnsTypePTR:
		names, err := resolver.LookupAddr(ctx, query.lookup)
		if err != nil {
			return dnsResult{}, fmt.Errorf("system PTR lookup for %q: %w", query.lookup, err)
		}
		for _, name := range names {
			result.Answers = append(result.Answers, dnsAnswer{Name: query.name, Type: query.record, Class: "IN", Value: dnsutil.Fqdn(name)})
		}
	}
	return result, nil
}

func resolveDirectDNS(ctx context.Context, query *dnsQuery, deps dnsDependencies) (dnsResult, error) {
	servers := []string{query.server}
	if query.server == "" {
		var err error
		servers, err = deps.configuredServers()
		if err != nil {
			return dnsResult{}, fmt.Errorf("read configured DNS servers: %w", err)
		}
		if len(servers) == 0 {
			return dnsResult{}, errNoConfiguredDNSServer
		}
	}
	request := dns.NewMsg(query.name, query.recordType)
	if request == nil {
		return dnsResult{}, fmt.Errorf("%w: unsupported direct record type %s", errInvalidDNSOptions, query.record)
	}
	var exchangeErrors []error
	for index, server := range servers {
		address, err := dnsServerAddress(server, query.port, query.portSet)
		if err != nil {
			exchangeErrors = append(exchangeErrors, err)
			continue
		}
		attemptContext, cancel := dnsAttemptContext(ctx, len(servers)-index)
		result, err := func() (dnsResult, error) {
			usedTransport := query.transport
			response, err := deps.exchange(attemptContext, request.Copy(), usedTransport, address)
			if err != nil {
				return dnsResult{}, fmt.Errorf("query %s over %s: %w", address, query.transport, err)
			}
			if err := validateDNSResponse(request, response); err != nil {
				return dnsResult{}, fmt.Errorf("validate response from %s: %w", address, err)
			}
			if query.transport == dnsTransportUDP && response.Truncated {
				usedTransport = dnsTransportTCP
				response, err = deps.exchange(attemptContext, request.Copy(), usedTransport, address)
				if err != nil {
					return dnsResult{}, fmt.Errorf("retry truncated response from %s over tcp: %w", address, err)
				}
			}
			if err := validateDNSResponse(request, response); err != nil {
				return dnsResult{}, fmt.Errorf("validate response from %s: %w", address, err)
			}
			return directDNSResult(query, address, usedTransport, response), nil
		}()
		cancel()
		if err != nil {
			exchangeErrors = append(exchangeErrors, err)
			continue
		}
		return result, nil
	}
	return dnsResult{}, fmt.Errorf("DNS query failed: %w", errors.Join(exchangeErrors...))
}

func dnsAttemptContext(parent context.Context, remainingServers int) (context.Context, context.CancelFunc) {
	deadline, ok := parent.Deadline()
	if !ok {
		return context.WithCancel(parent)
	}
	remaining := time.Until(deadline)
	return context.WithTimeout(parent, remaining/time.Duration(remainingServers))
}

func dnsServerAddress(server string, port int, portSet bool) (string, error) {
	if host, explicitPort, err := net.SplitHostPort(server); err == nil {
		validatedHost, err := dnsServerHost(host)
		if err != nil {
			return "", err
		}
		parsedPort, parseErr := strconv.ParseUint(explicitPort, 10, 16)
		if parseErr != nil || parsedPort == 0 {
			return "", fmt.Errorf("%w: invalid @server port %q", errInvalidDNSOptions, explicitPort)
		}
		if portSet && port != int(parsedPort) {
			return "", fmt.Errorf("%w: @server port %q conflicts with --port", errInvalidDNSOptions, explicitPort)
		}
		return net.JoinHostPort(validatedHost, strconv.FormatUint(parsedPort, 10)), nil
	}
	host, err := dnsServerHost(server)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func dnsServerHost(server string) (string, error) {
	if server == "" {
		return "", fmt.Errorf("%w: DNS server must not be empty", errInvalidDNSOptions)
	}
	if !strings.ContainsAny(server, "[]") {
		if !strings.Contains(server, ":") {
			return server, nil
		}
		address, err := netip.ParseAddr(server)
		if err != nil || !address.Is6() {
			return "", fmt.Errorf("%w: invalid DNS server %q", errInvalidDNSOptions, server)
		}
		return server, nil
	}
	if strings.Count(server, "[") != 1 || strings.Count(server, "]") != 1 ||
		!strings.HasPrefix(server, "[") || !strings.HasSuffix(server, "]") {

		return "", fmt.Errorf("%w: invalid DNS server %q", errInvalidDNSOptions, server)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	if host == "" {
		return "", fmt.Errorf("%w: invalid DNS server %q", errInvalidDNSOptions, server)
	}
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return "", fmt.Errorf("%w: invalid DNS server %q", errInvalidDNSOptions, server)
		}
	}
	return host, nil
}

func exchangeDNS(ctx context.Context, request *dns.Msg, network, address string) (*dns.Msg, error) {
	timeout := 100 * 365 * 24 * time.Hour
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial DNS server: %w", err)
	}
	cancelWatchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.SetDeadline(time.Now()) //nolint:errcheck // cancellation is best effort; the exchange reports its error
		case <-cancelWatchDone:
		}
	}()
	client := dns.NewClient()
	client.ReadTimeout = timeout
	client.WriteTimeout = timeout
	response, _, exchangeErr := client.ExchangeWithConn(ctx, request, connection)
	close(cancelWatchDone)
	closeErr := connection.Close()
	err = errors.Join(exchangeErr, closeErr)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, errors.Join(contextErr, err)
		}
		return nil, fmt.Errorf("exchange DNS message: %w", err)
	}
	return response, nil
}

func validateDNSResponse(request, response *dns.Msg) error {
	if response == nil {
		return fmt.Errorf("%w: empty response", errDNSResponseMismatch)
	}
	if !response.Response {
		return fmt.Errorf("%w: response bit is not set", errDNSResponseMismatch)
	}
	if response.ID != request.ID {
		return fmt.Errorf("%w: ID differs", errDNSResponseMismatch)
	}
	if response.Opcode != request.Opcode {
		return fmt.Errorf("%w: opcode differs", errDNSResponseMismatch)
	}
	if len(request.Question) != 1 || len(response.Question) != 1 {
		return fmt.Errorf("%w: question count", errDNSResponseMismatch)
	}
	want := request.Question[0]
	got := response.Question[0]
	if !strings.EqualFold(want.Header().Name, got.Header().Name) || dns.RRToType(want) != dns.RRToType(got) || want.Header().Class != got.Header().Class {
		return fmt.Errorf("%w: question differs", errDNSResponseMismatch)
	}
	return nil
}

func directDNSResult(query *dnsQuery, server, transport string, response *dns.Msg) dnsResult {
	status := dns.RcodeToString[response.Rcode]
	if status == "" {
		status = strconv.FormatUint(uint64(response.Rcode), 10)
	}
	result := dnsResult{
		Resolver: dnsResolverDirect, Server: &server, Transport: &transport,
		QueryName: dnsutil.Fqdn(query.name), QueryType: query.record, Status: &status,
		ID: &response.ID, Authoritative: &response.Authoritative, Truncated: &response.Truncated,
		RecursionAvailable: &response.RecursionAvailable, Answers: make([]dnsAnswer, 0, len(response.Answer)),
	}
	for _, record := range response.Answer {
		ttl := record.Header().TTL
		class := dns.ClassToString[record.Header().Class]
		if class == "" {
			class = strconv.FormatUint(uint64(record.Header().Class), 10)
		}
		recordType := dns.TypeToString[dns.RRToType(record)]
		if recordType == "" {
			recordType = "TYPE" + strconv.FormatUint(uint64(dns.RRToType(record)), 10)
		}
		value := ""
		if data := record.Data(); data != nil {
			value = data.String()
		}
		result.Answers = append(result.Answers, dnsAnswer{Name: record.Header().Name, Type: recordType, Class: class, TTL: &ttl, Value: value})
	}
	return result
}

func renderDNSResult(result *dnsResult, format string, short bool) ([]byte, error) {
	if format == dnsFormatJSON {
		var value any = result
		if short {
			values := make([]string, 0, len(result.Answers))
			for _, answer := range result.Answers {
				values = append(values, answer.Value)
			}
			value = values
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal DNS result: %w", err)
		}
		return append(data, '\n'), nil
	}
	var output bytes.Buffer
	if short {
		for _, answer := range result.Answers {
			fmt.Fprintln(&output, asym.EscapeDiagnosticValue(answer.Value))
		}
		if output.Len() == 0 {
			return make([]byte, 0), nil
		}
		return output.Bytes(), nil
	}
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

func parseConfiguredDNSServers(input io.Reader) ([]string, error) {
	var servers []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan resolver configuration: %w", err)
	}
	return servers, nil
}
