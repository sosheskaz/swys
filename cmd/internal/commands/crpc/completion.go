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

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/connectrpc"
	"github.com/sosheskaz/swys/internal/httptransport"
	"github.com/sosheskaz/swys/internal/protoschema"
)

const completionTimeout = 2 * time.Second

type completionKind uint8

const (
	completeMethod completionKind = iota
	completeService
	completeSymbol
)

func registerCompletion(command *cobra.Command, settings *options, lifecycle *commandio.Lifecycle) {
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 || hasDiscoveryFlag(cmd) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeSchema(cmd, args, prefix, settings, completeMethod)
	}
	for name, kind := range map[string]completionKind{flagList: completeService, flagDescribe: completeSymbol, flagTemplate: completeMethod} {
		register := func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 1 || incompatibleDiscovery(cmd, name) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeSchema(cmd, args, prefix, settings, kind)
		}
		mustComplete(command, name, register)
	}
	mustComplete(command, "format", formatCompletion(settings))
	mustComplete(command, flagStream, streamCompletion(settings))
	for _, name := range []string{flagData, flagHeader, "resolve", flagServerName, flagMaxMessageSize} {
		mustComplete(command, name, cobra.NoFileCompletions)
	}
	lifecycle.RegisterCompletion(func(completionCmd *cobra.Command, args []string) { prepareCompletion(completionCmd, args, command) })
}

func formatCompletion(settings *options) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		formats := []string{formatJSON, formatJSONL}
		mode, schemaErr := completionInvocationMode(cmd, args, settings)
		if schemaErr != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		target, err := selectTarget(args, settings)
		if err == nil && target.discovery && settings.template == "" {
			formats = []string{"text", "plain", formatJSON}
		}
		if settings.stream == streamServer || settings.stream == streamBidi || mode == streamServer || mode == streamBidi {
			formats = []string{formatJSONL}
		}
		return matching(formats, prefix), cobra.ShellCompDirectiveNoFileComp
	}
}

func streamCompletion(settings *options) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if hasDiscoveryFlag(cmd) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		mode, err := completionInvocationMode(cmd, args, settings)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		modes := []string{streamUnary, streamServer, streamClient, streamBidi}
		if mode != "" {
			modes = []string{mode}
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

func mustComplete(command *cobra.Command, name string, fn cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, fn); err != nil {
		panic(err)
	}
}

func completeSchema(cmd *cobra.Command, args []string, prefix string, settings *options, kind completionKind) ([]string, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if kind == completeMethod && !strings.Contains(prefix, "/") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	schema, err := boundedCompletionSchema(cmd, args, prefix, settings, kind)
	if err != nil {
		return nil, directive
	}
	return schemaCandidates(schema, prefix, settings, kind), directive
}

func boundedCompletionSchema(cmd *cobra.Command, args []string, prefix string, settings *options, kind completionKind) (*protoschema.Schema, error) {
	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()
	previous := cmd.Context()
	cmd.SetContext(ctx)
	defer cmd.SetContext(previous)
	schema, err := completionSchema(cmd, args, prefix, settings, kind)
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("complete Connect schema: %w", ctx.Err())
	}
	return schema, err
}

func completionInvocationMode(cmd *cobra.Command, args []string, settings *options) (string, error) {
	if settings.protoset == "" && !settings.reflectSchema {
		return "", nil
	}
	target, err := selectTarget(args, settings)
	if err != nil || target.discovery {
		return "", err
	}
	selector := strings.TrimPrefix(target.endpoint.Procedure, "/")
	schema, err := boundedCompletionSchema(cmd, []string{target.base.String()}, selector, settings, completeMethod)
	if err != nil {
		return "", err
	}
	method, err := schema.Method(selector)
	if err != nil {
		return "", err
	}
	return methodMode(method), nil
}

func completionSchema(cmd *cobra.Command, args []string, prefix string, settings *options, kind completionKind) (*protoschema.Schema, error) {
	if settings.connectTimeout < 0 || settings.reflectionTimeout < 0 || settings.protoset != "" && settings.reflectSchema {
		return nil, ErrInvalidFlags
	}
	if cmd.Flags().Changed(flagProtoset) {
		if !regularFiles(settings.protoset) {
			return nil, ErrInvalidFlags
		}
		return loadProtoset(cmd, settings.protoset)
	}
	if len(args) != 1 {
		return nil, ErrInvalidFlags
	}
	return remoteCompletionSchema(cmd, args[0], prefix, settings, kind)
}

func remoteCompletionSchema(cmd *cobra.Command, address, prefix string, settings *options, kind completionKind) (*protoschema.Schema, error) {
	if !regularFiles(settings.ca, settings.cert, settings.key) || tlsconfig.UsesStdin(cmd) {
		return nil, ErrInvalidFlags
	}
	base, err := connectrpc.ParseBase(address)
	if err != nil {
		return nil, err
	}
	copied := *settings
	copied.discovery = true
	if err := validateTLS(cmd, &copied, base.Scheme == "https"); err != nil {
		return nil, err
	}
	headers, err := parseHeaders(completionArray(settings.headers))
	if err != nil {
		return nil, err
	}
	resolver, err := httptransport.ParseResolves(completionArray(settings.resolves))
	if err != nil {
		return nil, err
	}
	tlsOptions, err := prepareTLS(cmd, &copied)
	if err != nil {
		return nil, err
	}
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.reflectionTimeout)
	defer cancel()
	ctx, _ = callContext(ctx, headers)
	connection := connectrpc.Options{TLS: tlsOptions, Resolves: resolver, ConnectTimeout: settings.connectTimeout}
	return reflectCompletion(ctx, base, connection, prefix, kind)
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

func schemaCandidates(schema *protoschema.Schema, prefix string, settings *options, kind completionKind) []string {
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
		addMethods(file.Services(), settings.stream, kind, add)
		if kind == completeSymbol {
			addMessageSymbols(file.Messages(), add)
			addEnums(file.Enums(), add)
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func addMethods(services protoreflect.ServiceDescriptors, selectedMode string, kind completionKind, add func(string, string)) {
	for i := range services.Len() {
		service := services.Get(i)
		for j := range service.Methods().Len() {
			method := service.Methods().Get(j)
			mode := methodMode(method)
			if kind == completeMethod && selectedMode != "" && selectedMode != mode {
				continue
			}
			name := string(method.FullName())
			if kind == completeMethod {
				name = string(service.FullName()) + "/" + string(method.Name())
			}
			add(name, fmt.Sprintf("%s: %s -> %s", mode, method.Input().FullName(), method.Output().FullName()))
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
	if !tlsApplicable(probe, probe.Flags().Args()) {
		hide(flagCA, flagSystemCA, flagCert, flagKey, flagServerName, flagInsecure)
	}
	if probe.Flag(flagCA).Value.String() == "" {
		hide(flagSystemCA)
	}
}
