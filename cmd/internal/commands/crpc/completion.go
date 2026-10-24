package crpc

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/sosheskaz/swys/cmd/internal/cli/auth"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/connectrpc"
	"github.com/sosheskaz/swys/internal/protoschema"
	"github.com/sosheskaz/swys/internal/textdisplay"
)

const (
	completionTimeout = 2 * time.Second
	// dataCompletionLimit keeps an inserted template editable on a command line.
	dataCompletionLimit = 2 << 10
)

type completionKind uint8

const (
	completeMethod completionKind = iota
	completeService
	completeSymbol
)

// completionPlaceholders fill the word being completed with a valid value so
// that the completed line can be validated as execution would; the empty key
// is the positional method.
var completionPlaceholders = map[string]string{
	"": "placeholder.Service/Method", flagList: "placeholder.Service", flagDescribe: "placeholder.Symbol",
	flagTemplate: "placeholder.Service/Method", flagData: "{}", flagStream: streamUnary, "format": formatJSON,
}

func registerCompletion(command *cobra.Command, settings *options, lifecycle *commandio.Lifecycle) {
	// words holds the completion request's words, from the command name through
	// the word being completed, once prepareCompletion has seen them.
	var words []string
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeSchema(cmd, words, prefix, "", completeMethod)
	}
	for name, kind := range map[string]completionKind{flagList: completeService, flagDescribe: completeSymbol, flagTemplate: completeMethod} {
		register := func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			return completeSchema(cmd, words, prefix, name, kind)
		}
		mustComplete(command, name, register)
	}
	mustComplete(command, "format", formatCompletion(settings, &words))
	mustComplete(command, flagStream, streamCompletion(settings, &words))
	mustComplete(command, flagData, dataCompletion(&words))
	for _, name := range []string{flagHeader, "resolve", flagServerName, flagMaxMessageSize} {
		mustComplete(command, name, cobra.NoFileCompletions)
	}
	lifecycle.RegisterCompletion(func(completionCmd *cobra.Command, args []string) {
		if prepareCompletion(completionCmd, args, command) {
			words = slices.Clone(args)
		}
	})
}

// completion is the line being completed, parsed afresh as execution would
// parse it, with the word being completed filled by a valid placeholder, after
// it passed execution's checks.
type completion struct {
	cmd      *cobra.Command
	settings *options
	validatedLine
}

// completionLine parses and validates the completed line on a probe command.
// Cobra drops the word being completed and its flag token before calling a
// completion function, which changes how shorthand clusters such as -td parse,
// so the probe reparses the original words. The typed word keeps whatever
// precedes prefix, such as a --flag= assignment, because the shell inserts a
// candidate only in place of prefix. It assumes the user will supply the
// request with -d unless the line already selects stdin explicitly, so it never
// consults stdin's state. Callers bound later work with the probe's context.
func completionLine(cmd *cobra.Command, words []string, slot, prefix string) (completion, error) {
	if len(words) == 0 || !strings.HasSuffix(words[len(words)-1], prefix) {
		return completion{}, ErrInvalidFlags
	}
	typed := words[len(words)-1]
	fill := typed[:len(typed)-len(prefix)] + completionPlaceholders[slot]
	root := commandio.NewProbeRoot()
	presentation.AddFlags(root)
	lifecycle := commandio.NewLifecycle()
	probe, settings := newCommand(lifecycle)
	root.AddCommand(probe)
	found, remaining, err := root.Find(append(slices.Clone(words[:len(words)-1]), fill))
	if err != nil || found != probe {
		return completion{}, ErrInvalidFlags
	}
	if err := probe.ParseFlags(remaining); err != nil {
		return completion{}, fmt.Errorf("parse completed line: %w", err)
	}
	probe.SetContext(cmd.Context())
	probe.SetIn(cmd.InOrStdin())
	args := probe.Flags().Args()
	if err := probe.ValidateArgs(args); err != nil {
		return completion{}, fmt.Errorf("validate completed arguments: %w", err)
	}
	if _, err := presentation.Policy(probe); err != nil {
		return completion{}, fmt.Errorf("validate completed line: %w", err)
	}
	if err := lifecycle.ValidateIO(probe); err != nil {
		return completion{}, err
	}
	line, err := validateLine(probe, args, settings, func() bool { return false })
	return completion{cmd: probe, settings: settings, validatedLine: line}, err
}

func formatCompletion(settings *options, words *[]string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
		defer cancel()
		line, err := completionLine(cmd, *words, "format", prefix)
		if err == nil {
			line.cmd.SetContext(ctx)
		}
		formats := []string{formatJSON, formatJSONL}
		switch {
		case err == nil && line.target.discovery:
			if line.settings.template == "" {
				formats = []string{"text", "plain", formatJSON}
			}
		case err == nil:
			formats, err = invocationValues(line, &line.settings.format, formats)
		case schemaSelected(settings):
		default:
			// Static values need no valid line, as when flags precede the URL.
			err = nil
			if settings.stream == streamServer || settings.stream == streamBidi {
				formats = []string{formatJSONL}
			}
		}
		if err != nil || ctx.Err() != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return matching(formats, prefix), cobra.ShellCompDirectiveNoFileComp
	}
}

func streamCompletion(settings *options, words *[]string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
		defer cancel()
		line, err := completionLine(cmd, *words, flagStream, prefix)
		if err == nil {
			line.cmd.SetContext(ctx)
		}
		modes := []string{streamUnary, streamServer, streamClient, streamBidi}
		switch {
		case err == nil:
			modes, err = invocationValues(line, &line.settings.stream, modes)
		case !hasDiscoveryFlag(cmd) && !schemaSelected(settings):
			// Static values need no valid line, as when flags precede the URL.
			err = nil
		}
		if err != nil || ctx.Err() != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		descriptions := map[string]string{
			streamUnary: "One request and one response", streamServer: "One request and many responses",
			streamClient: "Many requests and one response", streamBidi: "Messages in both directions; requires HTTP/2",
		}
		values := matching(modes, prefix)
		for i, value := range values {
			values[i] = cobra.CompletionWithDesc(value, descriptions[value])
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func schemaSelected(settings *options) bool {
	return settings.protoset != "" || settings.reflectSchema
}

// invocationValues keeps the candidates for option, a setting of the probe,
// for which execution accepts the line's method.
func invocationValues(line completion, option *string, candidates []string) ([]string, error) {
	schema, err := invocationSchema(line, false)
	if err != nil {
		return nil, err
	}
	validate, err := requestValidator(line)
	if err != nil {
		return nil, err
	}
	// Every candidate selects the same method, so the request is checked once.
	var request error
	checked := false
	return slices.DeleteFunc(candidates, func(value string) bool {
		*option = value
		method, _, err := invocationMethod(line.cmd, line.settings, schema, line.target.endpoint.Procedure)
		if err != nil {
			return true
		}
		if !checked {
			request, checked = validate(method, schema), true
		}
		return request != nil
	}), nil
}

// invocationAccepted applies execution's checks of the method and of a literal
// -d request once schema, which may be nil, is known.
func invocationAccepted(line completion, schema *protoschema.Schema, procedure string) error {
	method, _, err := invocationMethod(line.cmd, line.settings, schema, procedure)
	if err != nil {
		return err
	}
	return requestAccepted(line, method, schema)
}

func requestAccepted(line completion, method protoreflect.MethodDescriptor, schema *protoschema.Schema) error {
	validate, err := requestValidator(line)
	if err != nil {
		return err
	}
	return validate(method, schema)
}

// requestValidator applies execution's checks of the line's request source
// once and returns the check of a literal -d request against a method.
func requestValidator(line completion) (func(protoreflect.MethodDescriptor, *protoschema.Schema) error, error) {
	cmd := line.cmd
	accepted := func(protoreflect.MethodDescriptor, *protoschema.Schema) error { return nil }
	if input := cmd.Flag(flagInput).Value.String(); cmd.Flags().Changed(flagInput) && input != "-" {
		// Execution opens the input before it uses the network; stat it without reading.
		if input == "" || !regularFiles(input) {
			return nil, ErrInvalidFlags
		}
		return accepted, nil
	}
	if !cmd.Flags().Changed(flagData) {
		return accepted, nil
	}
	data, err := readRequest(cmd, line.settings)
	if err != nil {
		return nil, err
	}
	return func(method protoreflect.MethodDescriptor, schema *protoschema.Schema) error {
		_, err := validateMessage(data, method, schema)
		return err
	}, nil
}

// dataCompletion offers the selected method's compact request template.
func dataCompletion(words *[]string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
		defer cancel()
		line, err := completionLine(cmd, *words, flagData, prefix)
		if err == nil {
			line.cmd.SetContext(ctx)
		}
		if err != nil || line.target.discovery {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		probe := line.cmd
		if dataQuiet(probe) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		procedure := line.target.endpoint.Procedure
		// Execution checks these without a schema before reflecting on demand.
		if _, _, err := invocationMethod(probe, line.settings, nil, procedure); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		schema, err := invocationSchema(line, true)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		method, _, err := invocationMethod(probe, line.settings, schema, procedure)
		if err != nil || method == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		data, err := protoschema.TemplateJSON(method.Input(), false)
		// Shells display the candidate and insert it verbatim, so escape it like
		// --template output before applying the limit. Shells match the candidate
		// against the typed word, which may start with a quote.
		data = textdisplay.EscapeJSONControls(data)
		if err != nil || len(data) > dataCompletionLimit || !strings.HasPrefix(string(data), strings.TrimLeft(prefix, `'"`)) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		line.settings.data = string(data)
		if requestAccepted(line, method, schema) != nil || ctx.Err() != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{cobra.CompletionWithDesc(string(data), string(method.Input().FullName()))}, cobra.ShellCompDirectiveNoFileComp
	}
}

// dataQuiet reports a line beside which -d offers no template: --input owns
// the request, discovery takes none, or a TLS or credential file is stdin.
func dataQuiet(probe *cobra.Command) bool {
	return probe.Flags().Changed(flagInput) || hasDiscoveryFlag(probe) || tlsconfig.UsesStdin(probe) || auth.UsesStdin(probe.Flags())
}

func mustComplete(command *cobra.Command, name string, fn cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, fn); err != nil {
		panic(err)
	}
}

func completeSchema(cmd *cobra.Command, words []string, prefix, slot string, kind completionKind) ([]string, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if kind == completeMethod && !strings.Contains(prefix, "/") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()
	line, err := completionLine(cmd, words, slot, prefix)
	if err != nil {
		return nil, directive
	}
	line.cmd.SetContext(ctx)
	if slot == "" {
		// Execution checks these without a schema before reflecting on demand.
		if invocationAccepted(line, nil, line.target.endpoint.Procedure) != nil {
			return nil, directive
		}
	}
	schema, err := boundedCompletionSchema(line, prefix, kind)
	if err != nil {
		return nil, directive
	}
	accept := func(string) bool { return true }
	if slot == "" {
		validate, err := requestValidator(line)
		if err != nil {
			return nil, directive
		}
		// Methods often share an input type, which decides the request check.
		inputs := make(map[protoreflect.FullName]error)
		accept = func(name string) bool {
			if ctx.Err() != nil {
				return false
			}
			method, _, err := invocationMethod(line.cmd, line.settings, schema, name)
			if err != nil {
				return false
			}
			input := method.Input().FullName()
			result, checked := inputs[input]
			if !checked {
				result = validate(method, schema)
				inputs[input] = result
			}
			return result == nil
		}
	}
	values := schemaCandidates(schema, prefix, kind, accept)
	if ctx.Err() != nil {
		return nil, directive
	}
	return values, directive
}

func boundedCompletionSchema(line completion, prefix string, kind completionKind) (*protoschema.Schema, error) {
	cmd := line.cmd
	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()
	previous := cmd.Context()
	cmd.SetContext(ctx)
	defer cmd.SetContext(previous)
	schema, err := completionSchema(line, prefix, kind)
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("complete Connect schema: %w", ctx.Err())
	}
	return schema, err
}

// invocationSchema loads the schema for an invocation line's method. Without
// onDemand it uses only a schema source the line selects, and is nil otherwise.
func invocationSchema(line completion, onDemand bool) (*protoschema.Schema, error) {
	if !onDemand && !schemaSelected(line.settings) {
		return nil, nil //nolint:nilnil // no selected schema source means schema-free invocation
	}
	selector := strings.TrimPrefix(line.target.endpoint.Procedure, "/")
	return boundedCompletionSchema(line, selector, completeMethod)
}

func completionSchema(line completion, prefix string, kind completionKind) (*protoschema.Schema, error) {
	cmd, settings := line.cmd, line.settings
	// Execution reads these before it loads a schema; stat them without reading.
	credentialFiles := make([]string, 0, 3+len(auth.FileFlagNames))
	credentialFiles = append(credentialFiles, settings.ca, settings.cert, settings.key)
	for _, name := range auth.FileFlagNames {
		credentialFiles = append(credentialFiles, cmd.Flag(name).Value.String())
	}
	if !regularFiles(slices.DeleteFunc(credentialFiles, func(path string) bool { return path == "-" })...) {
		return nil, ErrInvalidFlags
	}
	if settings.protoset != "" {
		// Inline credentials are part of the line, and execution checks them before
		// loading a schema; file and environment sources stay unread offline.
		if source, _ := auth.Selected(cmd.Flags()); source == auth.BearerFlagName || source == auth.BasicFlagName {
			if err := applyAuthorization(cmd, line.headers); err != nil {
				return nil, err
			}
		}
		if !regularFiles(settings.protoset) {
			return nil, ErrInvalidFlags
		}
		return loadProtoset(cmd, settings.protoset)
	}
	if line.target.base == nil {
		return nil, ErrInvalidFlags
	}
	return remoteCompletionSchema(line, prefix, kind)
}

func remoteCompletionSchema(line completion, prefix string, kind completionKind) (*protoschema.Schema, error) {
	cmd, settings := line.cmd, line.settings
	if tlsconfig.UsesStdin(cmd) || auth.UsesStdin(cmd.Flags()) {
		return nil, ErrInvalidFlags
	}
	if err := applyAuthorization(cmd, line.headers); err != nil {
		return nil, err
	}
	tlsOptions, err := prepareTLS(cmd, settings)
	if err != nil {
		return nil, err
	}
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.reflectionTimeout)
	defer cancel()
	ctx, _ = callContext(ctx, line.headers)
	connection := connectrpc.Options{TLS: tlsOptions, Resolves: line.resolver, ConnectTimeout: settings.connectTimeout}
	return reflectCompletion(ctx, line.target.base, connection, prefix, kind)
}

func reflectCompletion(ctx context.Context, base *url.URL, connection connectrpc.Options, prefix string, kind completionKind) (*protoschema.Schema, error) {
	setup := connection.ConnectTimeout
	if deadline, ok := ctx.Deadline(); ok && (setup == 0 || time.Until(deadline) < setup) {
		// net/http may let an in-flight dial outlive a canceled request.
		setup = max(time.Until(deadline), time.Nanosecond)
	}
	connection.ConnectTimeout = setup
	symbol := ""
	if kind == completeMethod && strings.Contains(prefix, "/") {
		symbol, _, _ = strings.Cut(prefix, "/")
	}
	schema, err := connectrpc.Reflect(ctx, base, connection, symbol)
	if err != nil {
		return nil, err
	}
	if kind == completeSymbol {
		for _, service := range schema.Services {
			if strings.HasPrefix(prefix, service+".") {
				return connectrpc.Reflect(ctx, base, connection, service)
			}
		}
	}
	return schema, nil
}

func regularFiles(paths ...string) bool {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if path == "-" {
			return false
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func matching(values []string, prefix string) []string {
	return slices.DeleteFunc(values, func(value string) bool { return !strings.HasPrefix(value, prefix) })
}

func schemaCandidates(schema *protoschema.Schema, prefix string, kind completionKind, accept func(string) bool) []string {
	var values []string
	add := func(name, description string) {
		if len(values) < 256 && strings.HasPrefix(name, prefix) {
			values = append(values, cobra.CompletionWithDesc(name, description))
		}
	}
	// Acceptance may validate a request, so it runs only for words add would keep.
	wanted := func(name string) bool { return len(values) < 256 && strings.HasPrefix(name, prefix) }
	for _, service := range schema.Services {
		name := service
		if kind == completeMethod {
			if !wanted(name+"/") || !acceptsAnyMethod(schema, service, accept) {
				continue
			}
			name += "/"
		}
		add(name, "service")
	}
	if schema.Files == nil || kind == completeService || kind == completeMethod && !strings.Contains(prefix, "/") {
		return values
	}
	var files []protoreflect.FileDescriptor
	schema.Files.RangeFiles(func(file protoreflect.FileDescriptor) bool { files = append(files, file); return true })
	slices.SortFunc(files, func(a, b protoreflect.FileDescriptor) int { return strings.Compare(a.Path(), b.Path()) })
	for _, file := range files {
		addMethods(file.Services(), kind, func(name string) bool { return wanted(name) && accept(name) }, add)
		if kind == completeSymbol {
			addMessageSymbols(file.Messages(), add)
			addEnums(file.Enums(), add)
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// acceptsAnyMethod reports whether service has a method accept allows, so a
// service prefix leads somewhere. Without descriptors, every service may.
func acceptsAnyMethod(schema *protoschema.Schema, service string, accept func(string) bool) bool {
	if schema.Files == nil {
		return true
	}
	descriptor, err := schema.Files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return false
	}
	serviceDescriptor, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return false
	}
	methods := serviceDescriptor.Methods()
	for i := range methods.Len() {
		if accept(service + "/" + string(methods.Get(i).Name())) {
			return true
		}
	}
	return false
}

func addMethods(services protoreflect.ServiceDescriptors, kind completionKind, accept func(string) bool, add func(string, string)) {
	for i := range services.Len() {
		service := services.Get(i)
		for j := range service.Methods().Len() {
			method := service.Methods().Get(j)
			name := string(method.FullName())
			if kind == completeMethod {
				name = string(service.FullName()) + "/" + string(method.Name())
				if !accept(name) {
					continue
				}
			}
			add(name, fmt.Sprintf("%s: %s -> %s", methodMode(method), method.Input().FullName(), method.Output().FullName()))
		}
	}
}

func methodMode(method protoreflect.MethodDescriptor) string {
	if method.IsStreamingClient() && method.IsStreamingServer() {
		return streamBidi
	}
	if method.IsStreamingClient() {
		return streamClient
	}
	if method.IsStreamingServer() {
		return streamServer
	}
	return streamUnary
}

func addMessageSymbols(messages protoreflect.MessageDescriptors, add func(string, string)) {
	for i := range messages.Len() {
		message := messages.Get(i)
		if message.IsMapEntry() {
			continue
		}
		add(string(message.FullName()), "message")
		for j := range message.Fields().Len() {
			add(string(message.Fields().Get(j).FullName()), "field")
		}
		addMessageSymbols(message.Messages(), add)
		addEnums(message.Enums(), add)
	}
}

func addEnums(enums protoreflect.EnumDescriptors, add func(string, string)) {
	for i := range enums.Len() {
		enum := enums.Get(i)
		add(string(enum.FullName()), "enum")
		for j := range enum.Values().Len() {
			add(string(enum.Values().Get(j).FullName()), "enum value")
		}
	}
}

func hasDiscoveryFlag(cmd *cobra.Command) bool {
	return cmd.Flags().Changed(flagList) || cmd.Flags().Changed(flagDescribe) || cmd.Flags().Changed(flagTemplate)
}

func incompatibleDiscovery(cmd *cobra.Command, selected string) bool {
	for _, name := range []string{
		flagList, flagDescribe, flagTemplate,
		flagData, flagInput, flagInputEncoding, flagStdin, flagStream, flagWait, flagTimeout, flagMaxMessageSize,
	} {
		if name != selected && cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

// prepareCompletion reports whether a completion request completes command.
func prepareCompletion(completionCmd *cobra.Command, args []string, command *cobra.Command) bool {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return false
	}
	completed := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completed)
	if err != nil || actual != command {
		return false
	}
	root := commandio.NewProbeRoot()
	root.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, remaining, err := root.Find(completed)
	if err == nil && probe.ParseFlags(remaining) == nil {
		hideInapplicableFlags(command, probe)
	}
	return true
}

func hideInapplicableFlags(command, probe *cobra.Command) {
	hide := func(names ...string) {
		for _, name := range names {
			if flag := command.Flag(name); flag != nil {
				flag.Hidden = true
			}
		}
	}
	if hasDiscoveryFlag(probe) {
		hide(flagData, flagInput, flagInputEncoding, flagStdin, flagStream, flagWait, flagTimeout, flagMaxMessageSize)
	}
	for _, name := range []string{flagList, flagDescribe, flagTemplate} {
		if incompatibleDiscovery(probe, name) {
			hide(name)
		}
	}
	if probe.Flags().Changed(flagData) {
		hide(flagInput, flagStdin)
	}
	if probe.Flags().Changed(flagInput) {
		hide(flagData, flagStdin)
	}
	if probe.Flags().Changed(flagProtoset) {
		hide(flagReflect, flagReflectionTimeout)
	}
	if probe.Flags().Changed(flagReflect) {
		hide(flagProtoset)
	}
	headers, _ := probe.Flags().GetStringArray(flagHeader) //nolint:errcheck // a missing value hides nothing
	hide(auth.HiddenForCompletion(probe.Flags(), headers)...)
	hideInapplicableTLSFlags(probe, hide)
}

func hideInapplicableTLSFlags(probe *cobra.Command, hide func(...string)) {
	if !tlsApplicable(probe, probe.Flags().Args()) {
		hide(flagCA, flagSystemCA, flagCert, flagKey, flagServerName, flagInsecureNoVerify)
		if _, credential := auth.Selected(probe.Flags()); !credential {
			hide(flagInsecure)
		}
	}
	// Both are accepted together, but trust roots and verification carve-outs are never suggested together.
	if tlsconfig.SkipVerifyFlag(probe.Flags()) != "" {
		hide(flagCA, flagSystemCA)
	}
	if probe.Flag(flagCA).Value.String() != "" || probe.Flag(flagSystemCA).Value.String() == "true" {
		hide(flagInsecure, flagInsecureNoVerify)
	}
	if probe.Flag(flagCA).Value.String() == "" {
		hide(flagSystemCA)
	}
}
