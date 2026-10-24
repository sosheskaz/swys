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
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeSchema(cmd, args, prefix, settings, lifecycle, "", completeMethod)
	}
	for name, kind := range map[string]completionKind{flagList: completeService, flagDescribe: completeSymbol, flagTemplate: completeMethod} {
		register := func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
			return completeSchema(cmd, args, prefix, settings, lifecycle, name, kind)
		}
		mustComplete(command, name, register)
	}
	mustComplete(command, "format", formatCompletion(settings, lifecycle))
	mustComplete(command, flagStream, streamCompletion(settings, lifecycle))
	mustComplete(command, flagData, dataCompletion(settings, lifecycle))
	for _, name := range []string{flagHeader, "resolve", flagServerName, flagMaxMessageSize} {
		mustComplete(command, name, cobra.NoFileCompletions)
	}
	lifecycle.RegisterCompletion(func(completionCmd *cobra.Command, args []string) { prepareCompletion(completionCmd, args, command) })
}

// completionLine validates the line being completed, with slot filled by its
// placeholder, using execution's own checks. It assumes the user will supply
// the request with -d unless the line already selects stdin explicitly, so it
// never consults stdin's state.
func completionLine(
	cmd *cobra.Command, args []string, settings *options, lifecycle *commandio.Lifecycle, slot string,
) (validatedLine, error) {
	if slot == "" {
		args = append(slices.Clone(args), completionPlaceholders[slot])
	} else if err := cmd.Flags().Set(slot, completionPlaceholders[slot]); err != nil {
		return validatedLine{}, fmt.Errorf("fill completion placeholder: %w", err)
	}
	// Cobra skips positional argument validation during completion.
	if err := cmd.ValidateArgs(args); err != nil {
		return validatedLine{}, fmt.Errorf("validate completed arguments: %w", err)
	}
	if err := lifecycle.ValidateIO(cmd); err != nil {
		return validatedLine{}, err
	}
	settings.headers = completionArray(settings.headers)
	settings.resolves = completionArray(settings.resolves)
	return validateLine(cmd, args, settings, func() bool { return false })
}

func formatCompletion(settings *options, lifecycle *commandio.Lifecycle) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		stream := settings.stream
		line, err := completionLine(cmd, args, settings, lifecycle, "format")
		formats := []string{formatJSON, formatJSONL}
		switch {
		case err == nil && line.target.discovery:
			if settings.template == "" {
				formats = []string{"text", "plain", formatJSON}
			}
		case err == nil:
			formats, err = invocationValues(cmd, settings, line, &settings.format, formats)
		case schemaSelected(settings):
		default:
			// Static values need no valid line, as when flags precede the URL.
			err = nil
			if stream == streamServer || stream == streamBidi {
				formats = []string{formatJSONL}
			}
		}
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return matching(formats, prefix), cobra.ShellCompDirectiveNoFileComp
	}
}

func streamCompletion(settings *options, lifecycle *commandio.Lifecycle) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		discovery := hasDiscoveryFlag(cmd)
		line, err := completionLine(cmd, args, settings, lifecycle, flagStream)
		modes := []string{streamUnary, streamServer, streamClient, streamBidi}
		switch {
		case err == nil:
			modes, err = invocationValues(cmd, settings, line, &settings.stream, modes)
		case !discovery && !schemaSelected(settings):
			// Static values need no valid line, as when flags precede the URL.
			err = nil
		}
		if err != nil {
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

// invocationValues keeps the candidates for option, a setting of the line, for
// which execution accepts the line's method.
func invocationValues(
	cmd *cobra.Command, settings *options, line validatedLine, option *string, candidates []string,
) ([]string, error) {
	schema, err := invocationSchema(cmd, settings, line, false)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(candidates, func(value string) bool {
		*option = value
		_, _, err := invocationMethod(cmd, settings, schema, line.target.endpoint.Procedure)
		return err != nil
	}), nil
}

// dataCompletion offers the selected method's compact request template.
func dataCompletion(settings *options, lifecycle *commandio.Lifecycle) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if cmd.Flags().Changed(flagInput) || hasDiscoveryFlag(cmd) || tlsconfig.UsesStdin(cmd) || auth.UsesStdin(cmd.Flags()) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		line, err := completionLine(cmd, args, settings, lifecycle, flagData)
		if err != nil || line.target.discovery {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		schema, err := invocationSchema(cmd, settings, line, true)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		method, _, err := invocationMethod(cmd, settings, schema, line.target.endpoint.Procedure)
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
		return []string{cobra.CompletionWithDesc(string(data), string(method.Input().FullName()))}, cobra.ShellCompDirectiveNoFileComp
	}
}

func mustComplete(command *cobra.Command, name string, fn cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, fn); err != nil {
		panic(err)
	}
}

func completeSchema(
	cmd *cobra.Command, args []string, prefix string, settings *options, lifecycle *commandio.Lifecycle, slot string, kind completionKind,
) ([]string, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if kind == completeMethod && !strings.Contains(prefix, "/") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	line, err := completionLine(cmd, args, settings, lifecycle, slot)
	if err != nil {
		return nil, directive
	}
	schema, err := boundedCompletionSchema(cmd, settings, line, prefix, kind)
	if err != nil {
		return nil, directive
	}
	accept := func(string) bool { return true }
	if slot == "" {
		accept = func(method string) bool {
			_, _, err := invocationMethod(cmd, settings, schema, method)
			return err == nil
		}
	}
	return schemaCandidates(schema, prefix, kind, accept), directive
}

func boundedCompletionSchema(
	cmd *cobra.Command, settings *options, line validatedLine, prefix string, kind completionKind,
) (*protoschema.Schema, error) {
	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()
	previous := cmd.Context()
	cmd.SetContext(ctx)
	defer cmd.SetContext(previous)
	schema, err := completionSchema(cmd, settings, line, prefix, kind)
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("complete Connect schema: %w", ctx.Err())
	}
	return schema, err
}

// invocationSchema loads the schema for an invocation line's method. Without
// onDemand it uses only a schema source the line selects, and is nil otherwise.
func invocationSchema(cmd *cobra.Command, settings *options, line validatedLine, onDemand bool) (*protoschema.Schema, error) {
	if !onDemand && !schemaSelected(settings) {
		return nil, nil //nolint:nilnil // no selected schema source means schema-free invocation
	}
	selector := strings.TrimPrefix(line.target.endpoint.Procedure, "/")
	return boundedCompletionSchema(cmd, settings, line, selector, completeMethod)
}

func completionSchema(
	cmd *cobra.Command, settings *options, line validatedLine, prefix string, kind completionKind,
) (*protoschema.Schema, error) {
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
		if !regularFiles(settings.protoset) {
			return nil, ErrInvalidFlags
		}
		return loadProtoset(cmd, settings.protoset)
	}
	if line.target.base == nil {
		return nil, ErrInvalidFlags
	}
	return remoteCompletionSchema(cmd, settings, line, prefix, kind)
}

func remoteCompletionSchema(
	cmd *cobra.Command, settings *options, line validatedLine, prefix string, kind completionKind,
) (*protoschema.Schema, error) {
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

func completionArray(values []string) []string {
	// Cobra parses StringArray flags twice during completion. Retain intentional
	// duplicates within the original arguments, but remove the repeated parse.
	middle := len(values) / 2
	if len(values)%2 == 0 && slices.Equal(values[:middle], values[middle:]) {
		return values[:middle]
	}
	return values
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
	for _, service := range schema.Services {
		name := service
		if kind == completeMethod {
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
		addMethods(file.Services(), kind, accept, add)
		if kind == completeSymbol {
			addMessageSymbols(file.Messages(), add)
			addEnums(file.Enums(), add)
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
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

func prepareCompletion(completionCmd *cobra.Command, args []string, command *cobra.Command) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completed := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completed)
	if err != nil || actual != command {
		return
	}
	root := commandio.NewProbeRoot()
	root.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, remaining, err := root.Find(completed)
	if err != nil || probe.ParseFlags(remaining) != nil {
		return
	}
	hideInapplicableFlags(command, probe)
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
