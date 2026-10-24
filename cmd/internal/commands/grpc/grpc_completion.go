package grpc

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/sosheskaz/swys/cmd/internal/cli/auth"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz/swys/internal/protoschema"
)

const (
	grpcCompletionTimeout = 2 * time.Second
	// grpcDataCompletionLimit keeps an inserted template editable on a command line.
	grpcDataCompletionLimit = 2 << 10
	grpcPlaintextFlagName   = "plaintext"
	grpcInsecureFlagName    = tlsconfig.InsecureFlagName
	grpcListFlagName        = "list"
	grpcDescribeFlagName    = "describe"
	grpcTemplateFlagName    = "template"
	grpcDataFlagName        = "data"
	grpcInputFlagName       = "input"
)

type grpcCompletionKind uint8

const (
	grpcCompleteSelector grpcCompletionKind = iota
	grpcCompleteService
	grpcCompleteSymbol
	grpcCompleteTemplate
)

func grpcTLSCompletionApplicable(cmd *cobra.Command, _ []string) bool {
	return cmd.Flag("plaintext").Value.String() == "false"
}

func registerGRPCCompletion(command *cobra.Command, options *grpcOptions, line *grpcCompletionLine) {
	registerGRPCSelectionCompletion(command, options, line)
	mustRegisterGRPCCompletion(command, grpcDataFlagName, func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		return completeGRPCData(cmd, args, prefix, options, line), cobra.ShellCompDirectiveNoFileComp
	})
	for _, name := range []string{"header", "max-message-size", tlsconfig.ServerNameFlagName, "timeout"} {
		mustRegisterGRPCCompletion(command, name, cobra.NoFileCompletions)
	}
	for _, name := range []string{tlsconfig.CAFlagName, tlsconfig.CertFlagName, tlsconfig.KeyFlagName} {
		flagName := name
		mustRegisterGRPCCompletion(command, name, func(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			if !grpcTLSCompletionAllowed(cmd, flagName) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveDefault
		})
	}
	for _, name := range []string{grpcPlaintextFlagName, grpcInsecureFlagName, tlsconfig.InsecureNoVerifyFlagName, tlsconfig.SystemCAFlagName} {
		flagName := name
		mustRegisterGRPCCompletion(command, name, func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			var values []string
			for _, candidate := range []bool{true, false} {
				value := strconv.FormatBool(candidate)
				if (!candidate || grpcTLSCompletionAllowed(cmd, flagName)) && strings.HasPrefix(value, prefix) {
					values = append(values, value)
				}
			}
			return values, cobra.ShellCompDirectiveNoFileComp
		})
	}
}

func registerGRPCSelectionCompletion(command *cobra.Command, options *grpcOptions, line *grpcCompletionLine) {
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 || !grpcSelectionCompletionAllowed(cmd, args, grpcCompleteSelector) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeGRPC(cmd, args, prefix, options, grpcCompleteSelector, line, "")
	}
	for name, kind := range map[string]grpcCompletionKind{
		grpcListFlagName:     grpcCompleteService,
		grpcDescribeFlagName: grpcCompleteSymbol,
		grpcTemplateFlagName: grpcCompleteTemplate,
	} {
		completionKind, flagName := kind, name
		mustRegisterGRPCCompletion(command, name, func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 1 || !grpcSelectionCompletionAllowed(cmd, args, completionKind) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			candidates := completionKind
			if candidates == grpcCompleteTemplate {
				// A template names the same unary SERVICE/METHOD as an invocation selector.
				candidates = grpcCompleteSelector
			}
			return completeGRPC(cmd, args, prefix, options, candidates, line, flagName)
		})
	}
}

func mustRegisterGRPCCompletion(command *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

// prepareGRPCCompletion hides inapplicable flags and returns the words before
// the one being completed when they address command.
func prepareGRPCCompletion(completionCmd *cobra.Command, args []string, command *cobra.Command) []string {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return nil
	}
	completedArgs := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || actual != command {
		return nil
	}
	probe := grpcCompletionProbe(completedArgs)
	if probe == nil {
		return completedArgs
	}
	for _, name := range []string{
		grpcPlaintextFlagName, grpcInsecureFlagName, tlsconfig.InsecureNoVerifyFlagName, tlsconfig.SystemCAFlagName,
		tlsconfig.CAFlagName, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.ServerNameFlagName,
	} {
		if !grpcTLSCompletionAllowed(probe, name) {
			command.Flag(name).Hidden = true
		}
	}
	headers, _ := probe.Flags().GetStringArray("header") //nolint:errcheck // a missing value hides nothing
	for _, name := range auth.HiddenForCompletion(probe.Flags(), headers) {
		command.Flag(name).Hidden = true
	}
	hideGRPCSelectionFlags(command, probe)
	return completedArgs
}

func hideGRPCSelectionFlags(command, probe *cobra.Command) {
	for name, kind := range map[string]grpcCompletionKind{
		grpcListFlagName:     grpcCompleteService,
		grpcDescribeFlagName: grpcCompleteSymbol,
		grpcTemplateFlagName: grpcCompleteTemplate,
	} {
		if !grpcSelectionCompletionAllowed(probe, probe.Flags().Args(), kind) {
			command.Flag(name).Hidden = true
		}
	}
	discovery := probe.Flags().Changed(grpcListFlagName) || probe.Flags().Changed(grpcDescribeFlagName) ||
		probe.Flags().Changed(grpcTemplateFlagName)
	command.Flag(grpcDataFlagName).Hidden = discovery || probe.Flags().Changed(grpcInputFlagName)
	command.Flag(grpcInputFlagName).Hidden = discovery || probe.Flags().Changed(grpcDataFlagName)
}

func grpcCompletionProbe(completedArgs []string) *cobra.Command {
	probeRoot := commandio.NewProbeRoot()
	probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, probeArgs, err := probeRoot.Find(completedArgs)
	if err != nil {
		return nil
	}
	if err := probe.ParseFlags(probeArgs); err != nil {
		if len(probeArgs) == 0 || (probeArgs[len(probeArgs)-1] != "--input" && probeArgs[len(probeArgs)-1] != "-i") {
			return nil
		}
		// An unfinished input option needs visibility for the shared callback.
		// Parse normally first so a flag-looking literal value remains a value;
		// retry on a fresh probe to discard the failed parse's partial state.
		probeRoot = commandio.NewProbeRoot()
		probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
		probe, probeArgs, err = probeRoot.Find(completedArgs[:len(completedArgs)-1])
		if err != nil || probe.ParseFlags(probeArgs) != nil {
			return nil
		}
	}
	return probe
}

// grpcCompletionLine holds the words before the one being completed. The
// completion hook records them before Cobra runs value callbacks.
type grpcCompletionLine struct {
	args []string
}

// validate runs execution's pre-network checks on the completed line with the
// word being completed, flag's value or the method selector when flag is empty,
// set to a valid placeholder. It decides request ownership from the line alone:
// completion never inspects stdin, so only --input - gives stdin the request.
func (line *grpcCompletionLine) validate(ctx context.Context, flag string) error {
	probe, options, args, err := line.probe(flag) //nolint:contextcheck // the probe is parsed, never executed
	if err != nil {
		return err
	}
	selector, selectorPresent := "", len(args) == 2
	if selectorPresent {
		selector = args[1]
	}
	payloadStdin := selectorPresent && !probe.Flags().Changed(grpcDataFlagName) &&
		probe.Flags().Changed(grpcInputFlagName) && grpcCompletionString(probe, grpcInputFlagName) == "-"
	if _, err := presentation.Policy(probe); err != nil {
		return fmt.Errorf("validate completed presentation: %w", err)
	}
	if err := validateGRPCOptions(probe, args[0], selector, selectorPresent, payloadStdin, options); err != nil {
		return err
	}
	md, err := parseGRPCMetadata(options.headers)
	if err != nil {
		return err
	}
	if err := auth.RejectHeader(probe.Flags(), len(md["authorization"]) != 0, ErrInvalidOptions); err != nil {
		return fmt.Errorf("validate completed credential: %w", err)
	}
	if source, ok := auth.Selected(probe.Flags()); ok && (source == auth.BearerFlagName || source == auth.BasicFlagName) {
		// A literal credential is already on the line; credential files and variables stay unread.
		if _, _, err := auth.Value(ctx, nil, probe.Flags(), nil, ErrInvalidOptions); err != nil {
			return fmt.Errorf("validate completed credential: %w", err)
		}
	}
	return grpcCompletionFilesUsable(probe, options, selectorPresent)
}

// probe parses the completed line on a fresh command and fills the completed word.
func (line *grpcCompletionLine) probe(flag string) (*cobra.Command, *grpcOptions, []string, error) {
	if line.args == nil {
		return nil, nil, nil, fmt.Errorf("%w: no completed command line", ErrInvalidOptions)
	}
	probe, options, err := parseGRPCCompletionLine(line.args)
	if last := len(line.args) - 1; err != nil && flag != "" && strings.HasPrefix(line.args[last], "-") {
		// A separate flag value leaves the completed flag's name as the last word.
		probe, options, err = parseGRPCCompletionLine(line.args[:last])
	}
	if err != nil {
		return nil, nil, nil, err
	}
	args := probe.Flags().Args()
	if flag == "" {
		args = append(args, grpcCompletionPlaceholder(flag))
	} else if err := probe.Flags().Set(flag, grpcCompletionPlaceholder(flag)); err != nil {
		return nil, nil, nil, fmt.Errorf("set completed --%s: %w", flag, err)
	}
	if err := probe.ValidateArgs(args); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	return probe, options, args, nil
}

func parseGRPCCompletionLine(args []string) (*cobra.Command, *grpcOptions, error) {
	probeRoot := commandio.NewProbeRoot()
	presentation.AddFlags(probeRoot)
	command, options := newGRPCCommand(commandio.NewLifecycle())
	probeRoot.AddCommand(command)
	probe, probeArgs, err := probeRoot.Find(args)
	if err != nil {
		return nil, nil, fmt.Errorf("find completed command: %w", err)
	}
	if probe != command {
		return nil, nil, fmt.Errorf("%w: completed line does not address grpc", ErrInvalidOptions)
	}
	if err := probe.ParseFlags(probeArgs); err != nil {
		return nil, nil, fmt.Errorf("parse completed flags: %w", err)
	}
	return probe, options, nil
}

func grpcCompletionPlaceholder(flag string) string {
	switch flag {
	case grpcListFlagName, grpcDescribeFlagName:
		return "a.B"
	case grpcDataFlagName:
		return "{}"
	default:
		return "a.B/C"
	}
}

// grpcCompletionFilesUsable stats, without opening, files execution reads before
// connecting: credential files, an invocation's request file, and TLS files
// whenever execution dials. Stdin selections are left to the callers' quiet rules.
func grpcCompletionFilesUsable(probe *cobra.Command, options *grpcOptions, selectorPresent bool) error {
	paths := make([]string, 0, 3+len(auth.FileFlagNames))
	for _, name := range auth.FileFlagNames {
		paths = append(paths, grpcCompletionString(probe, name))
	}
	if selectorPresent || !probe.Flags().Changed("protoset") {
		paths = append(paths, options.ca, options.cert, options.key)
	}
	for _, path := range paths {
		if path == "" || path == "-" {
			continue
		}
		if _, err := regularGRPCCompletionFile(path); err != nil {
			return err
		}
	}
	input := grpcCompletionString(probe, grpcInputFlagName)
	if !selectorPresent || probe.Flags().Changed(grpcDataFlagName) || !probe.Flags().Changed(grpcInputFlagName) || input == "-" {
		return nil
	}
	info, err := regularGRPCCompletionFile(input)
	if err != nil {
		return err
	}
	if limit := int64(options.maxMessageSize) * 4; info.Size() > limit {
		return fmt.Errorf("%w: request JSON exceeds %d bytes", ErrMessageLimit, limit)
	}
	return nil
}

func regularGRPCCompletionFile(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat completed file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidOptions, path)
	}
	return info, nil
}

func grpcSelectionCompletionAllowed(command *cobra.Command, args []string, kind grpcCompletionKind) bool {
	list := command.Flags().Changed(grpcListFlagName)
	describe := command.Flags().Changed(grpcDescribeFlagName)
	template := command.Flags().Changed(grpcTemplateFlagName)
	discovery := len(args) < 2 && !command.Flags().Changed(grpcDataFlagName) && !command.Flags().Changed(grpcInputFlagName)
	switch kind {
	case grpcCompleteSelector:
		return !list && !describe && !template
	case grpcCompleteService:
		return discovery && !describe && !template
	case grpcCompleteSymbol:
		return discovery && !list && !template
	case grpcCompleteTemplate:
		return discovery && !list && !describe
	default:
		return false
	}
}

func grpcCompletionBool(command *cobra.Command, name string) bool {
	value, err := command.Flags().GetBool(name)
	return err == nil && value
}

func grpcCompletionString(command *cobra.Command, name string) string {
	value, err := command.Flags().GetString(name)
	if err != nil {
		return ""
	}
	return value
}

// grpcTLSCompletionAllowed suggests only flags that can matter given those already typed.
// Every combination is accepted; trust roots and verification carve-outs are just never
// suggested together.
func grpcTLSCompletionAllowed(command *cobra.Command, name string) bool {
	plaintext := grpcCompletionBool(command, grpcPlaintextFlagName)
	trusted := grpcCompletionString(command, tlsconfig.CAFlagName) != "" || grpcCompletionBool(command, tlsconfig.SystemCAFlagName)
	switch name {
	case grpcPlaintextFlagName:
		return !trusted && !grpcCompletionHasTLSIdentity(command)
	case grpcInsecureFlagName:
		// Over --plaintext the umbrella matters only by permitting a credential.
		_, credential := auth.Selected(command.Flags())
		return !trusted && (!plaintext || credential)
	case tlsconfig.InsecureNoVerifyFlagName:
		return !trusted && !plaintext
	case tlsconfig.SystemCAFlagName, tlsconfig.CAFlagName:
		return !plaintext && tlsconfig.SkipVerifyFlag(command.Flags()) == ""
	default:
		return !plaintext
	}
}

func grpcCompletionHasTLSIdentity(command *cobra.Command) bool {
	return grpcCompletionString(command, tlsconfig.ServerNameFlagName) != "" ||
		grpcCompletionString(command, tlsconfig.CertFlagName) != "" || grpcCompletionString(command, tlsconfig.KeyFlagName) != ""
}

func completeGRPC(
	command *cobra.Command,
	args []string,
	prefix string,
	options *grpcOptions,
	kind grpcCompletionKind,
	line *grpcCompletionLine,
	flag string,
) ([]string, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if kind == grpcCompleteSelector && !strings.Contains(prefix, "/") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	if tlsconfig.UsesStdin(command) {
		return nil, directive
	}

	ctx, cancel := context.WithTimeout(command.Context(), grpcCompletionTimeout)
	defer cancel()
	schema, connection, reflectionCtx := grpcCompletionSchema(ctx, command, args[0], options, line, flag)
	if connection != nil {
		defer connection.Close() //nolint:errcheck // completion result is already collected
	}
	if schema == nil {
		return nil, directive
	}

	service := grpcCompletionService(schema.services, prefix, kind)
	if connection != nil && service != "" {
		var err error
		schema, _, err = reflectGRPCSchema(reflectionCtx, connection, service, "", "")
		if err != nil {
			return nil, directive
		}
	}
	return grpcCompletionCandidates(schema, prefix, kind), directive
}

func grpcDataCompletionApplicable(command *cobra.Command, args []string) bool {
	return len(args) == 2 && validGRPCMethodSelector(args[1]) && !command.Flags().Changed(grpcInputFlagName) &&
		grpcSelectionCompletionAllowed(command, args, grpcCompleteSelector) &&
		!tlsconfig.UsesStdin(command) && !auth.UsesStdin(command.Flags())
}

// completeGRPCData offers the selected method's compact request template.
func completeGRPCData(command *cobra.Command, args []string, prefix string, options *grpcOptions, line *grpcCompletionLine) []string {
	if !grpcDataCompletionApplicable(command, args) {
		return nil
	}
	ctx, cancel := context.WithTimeout(command.Context(), grpcCompletionTimeout)
	defer cancel()
	schema, connection, reflectionCtx := grpcCompletionSchema(ctx, command, args[0], options, line, grpcDataFlagName)
	if connection != nil {
		defer connection.Close() //nolint:errcheck // completion result is already collected
	}
	if schema == nil {
		return nil
	}
	if connection != nil {
		var err error
		if schema, _, err = reflectGRPCSchema(reflectionCtx, connection, args[1], "", ""); err != nil {
			return nil
		}
	}
	method, err := schema.findMethod(args[1])
	if err != nil || requireUnaryGRPCMethod(method, args[1]) != nil {
		return nil
	}
	data, err := protoschema.TemplateJSON(method.Input(), false)
	if err == nil {
		// Execution rejects an oversized --data before connecting.
		_, err = validateGRPCRequestSize(data, int64(options.maxMessageSize)*4)
	}
	// Shells match the candidate against the typed word, which may start with a quote.
	if err != nil || len(data) > grpcDataCompletionLimit || !strings.HasPrefix(string(data), strings.TrimLeft(prefix, `'"`)) {
		return nil
	}
	return []string{cobra.CompletionWithDesc(string(data), string(method.Input().FullName()))}
}

func grpcCompletionSchema(
	ctx context.Context,
	command *cobra.Command,
	endpoint string,
	options *grpcOptions,
	line *grpcCompletionLine,
	flag string,
) (*grpcSchema, *grpc.ClientConn, context.Context) {
	if line.validate(ctx, flag) != nil {
		return nil, nil, ctx
	}
	if command.Flags().Changed("protoset") {
		info, err := os.Stat(options.protoset)
		if err != nil || !info.Mode().IsRegular() {
			return nil, nil, ctx
		}
		schema, err := loadGRPCProtoset(options.protoset)
		return completionSchemaOrNil(schema, err), nil, ctx
	}

	requestMetadata, err := parseGRPCMetadata(grpcCompletionHeaders(options.headers))
	if err != nil || auth.UsesStdin(command.Flags()) ||
		applyGRPCAuthorization(command, requestMetadata) != nil {

		return nil, nil, ctx
	}
	ctx = metadata.NewOutgoingContext(ctx, requestMetadata)
	connection, _, err := dialGRPC(command, endpoint, options)
	if err != nil {
		return nil, nil, ctx
	}
	schema, _, err := reflectGRPCSchema(ctx, connection, "", "", "")
	if err != nil {
		return nil, connection, ctx
	}
	return schema, connection, ctx
}

func grpcCompletionHeaders(values []string) []string {
	// Cobra parses completion flags twice. StringArray appends on both passes, so
	// remove the repeated parse while preserving duplicates from the original argv.
	if len(values)%2 == 0 {
		middle := len(values) / 2
		if slices.Equal(values[:middle], values[middle:]) {
			return values[:middle]
		}
	}
	return values
}

func completionSchemaOrNil(schema *grpcSchema, err error) *grpcSchema {
	if err != nil {
		return nil
	}
	return schema
}

func grpcCompletionService(services []string, prefix string, kind grpcCompletionKind) string {
	var separator string
	switch kind {
	case grpcCompleteSelector:
		separator = "/"
	case grpcCompleteSymbol:
		separator = "."
	case grpcCompleteService, grpcCompleteTemplate:
		return ""
	}
	for _, service := range services {
		if protoreflect.FullName(service).IsValid() && strings.HasPrefix(prefix, service+separator) {
			return service
		}
	}
	return ""
}

func grpcCompletionCandidates(schema *grpcSchema, prefix string, kind grpcCompletionKind) []string {
	values := make([]string, 0, len(schema.services))
	for _, service := range schema.services {
		if !protoreflect.FullName(service).IsValid() {
			continue
		}
		candidate := service
		if kind == grpcCompleteSelector {
			candidate += "/"
		}
		if strings.HasPrefix(candidate, prefix) {
			values = append(values, candidate)
		}
	}

	if kind == grpcCompleteService {
		return sortedUniqueGRPCCompletions(values)
	}
	if kind == grpcCompleteSelector && grpcCompletionService(schema.services, prefix, kind) == "" {
		return sortedUniqueGRPCCompletions(values)
	}
	schema.files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		for serviceIndex := range file.Services().Len() {
			service := file.Services().Get(serviceIndex)
			values = append(values, grpcMethodCompletions(service, prefix, kind)...)
		}
		if kind == grpcCompleteSymbol {
			values = append(values, grpcMessageCompletions(file.Messages(), prefix)...)
			values = append(values, grpcEnumCompletions(file.Enums(), prefix)...)
		}
		return true
	})
	return sortedUniqueGRPCCompletions(values)
}

func grpcMethodCompletions(service protoreflect.ServiceDescriptor, prefix string, kind grpcCompletionKind) []string {
	separator := "/"
	if kind == grpcCompleteSymbol {
		separator = "."
	}
	var values []string
	for methodIndex := range service.Methods().Len() {
		method := service.Methods().Get(methodIndex)
		if kind == grpcCompleteSelector && (method.IsStreamingClient() || method.IsStreamingServer()) {
			continue
		}
		candidate := string(service.FullName()) + separator + string(method.Name())
		if strings.HasPrefix(candidate, prefix) {
			description := "method"
			if kind == grpcCompleteSelector {
				description = "unary " + string(method.Input().FullName()) + " -> " + string(method.Output().FullName())
			}
			values = append(values, cobra.CompletionWithDesc(candidate, description))
		}
	}
	return values
}

func grpcMessageCompletions(messages protoreflect.MessageDescriptors, prefix string) []string {
	var values []string
	for index := range messages.Len() {
		message := messages.Get(index)
		if message.IsMapEntry() {
			continue
		}
		if name := string(message.FullName()); strings.HasPrefix(name, prefix) {
			values = append(values, cobra.CompletionWithDesc(name, "message"))
		}
		values = append(values, grpcMessageCompletions(message.Messages(), prefix)...)
		values = append(values, grpcEnumCompletions(message.Enums(), prefix)...)
	}
	return values
}

func grpcEnumCompletions(enums protoreflect.EnumDescriptors, prefix string) []string {
	var values []string
	for index := range enums.Len() {
		if name := string(enums.Get(index).FullName()); strings.HasPrefix(name, prefix) {
			values = append(values, cobra.CompletionWithDesc(name, "enum"))
		}
	}
	return values
}

func sortedUniqueGRPCCompletions(values []string) []string {
	sort.Strings(values)
	return slices.Compact(values)
}
