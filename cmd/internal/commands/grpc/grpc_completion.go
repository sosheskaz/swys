package grpc

import (
	"context"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
)

const (
	grpcCompletionTimeout = 2 * time.Second
	grpcPlaintextFlagName = "plaintext"
	grpcInsecureFlagName  = "insecure"
	grpcListFlagName      = "list"
	grpcDescribeFlagName  = "describe"
	grpcDataFlagName      = "data"
	grpcInputFlagName     = "input"
)

type grpcCompletionKind uint8

const (
	grpcCompleteSelector grpcCompletionKind = iota
	grpcCompleteService
	grpcCompleteSymbol
)

func grpcTLSCompletionApplicable(cmd *cobra.Command, _ []string) bool {
	return cmd.Flag("plaintext").Value.String() == "false"
}

func registerGRPCCompletion(command *cobra.Command, options *grpcOptions) {
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 || !grpcSelectionCompletionAllowed(cmd, args, grpcCompleteSelector) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeGRPC(cmd, args, prefix, options, grpcCompleteSelector)
	}
	for name, kind := range map[string]grpcCompletionKind{
		grpcListFlagName:     grpcCompleteService,
		grpcDescribeFlagName: grpcCompleteSymbol,
	} {
		completionKind := kind
		if err := command.RegisterFlagCompletionFunc(name, func(
			cmd *cobra.Command,
			args []string,
			prefix string,
		) ([]string, cobra.ShellCompDirective) {
			if len(args) != 1 || !grpcSelectionCompletionAllowed(cmd, args, completionKind) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeGRPC(cmd, args, prefix, options, completionKind)
		}); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{grpcDataFlagName, "header", "max-message-size", tlsconfig.ServerNameFlagName, "timeout"} {
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
	for _, name := range []string{grpcPlaintextFlagName, grpcInsecureFlagName, tlsconfig.SystemCAFlagName} {
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

func mustRegisterGRPCCompletion(command *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

func prepareGRPCCompletion(completionCmd *cobra.Command, args []string, command *cobra.Command) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completedArgs := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || actual != command {
		return
	}
	probe := grpcCompletionProbe(completedArgs)
	if probe == nil {
		return
	}
	for _, name := range []string{
		grpcPlaintextFlagName, grpcInsecureFlagName, tlsconfig.SystemCAFlagName, tlsconfig.CAFlagName,
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.ServerNameFlagName,
	} {
		if !grpcTLSCompletionAllowed(probe, name) {
			command.Flag(name).Hidden = true
		}
	}
	for name, kind := range map[string]grpcCompletionKind{grpcListFlagName: grpcCompleteService, grpcDescribeFlagName: grpcCompleteSymbol} {
		if !grpcSelectionCompletionAllowed(probe, probe.Flags().Args(), kind) {
			command.Flag(name).Hidden = true
		}
	}
	discovery := probe.Flags().Changed(grpcListFlagName) || probe.Flags().Changed(grpcDescribeFlagName)
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

func grpcSelectionCompletionAllowed(command *cobra.Command, args []string, kind grpcCompletionKind) bool {
	switch kind {
	case grpcCompleteSelector:
		return !command.Flags().Changed(grpcListFlagName) && !command.Flags().Changed(grpcDescribeFlagName)
	case grpcCompleteService:
		return len(args) < 2 && !command.Flags().Changed(grpcDescribeFlagName) &&
			!command.Flags().Changed(grpcDataFlagName) && !command.Flags().Changed(grpcInputFlagName)
	case grpcCompleteSymbol:
		return len(args) < 2 && !command.Flags().Changed(grpcListFlagName) &&
			!command.Flags().Changed(grpcDataFlagName) && !command.Flags().Changed(grpcInputFlagName)
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

func grpcTLSCompletionAllowed(command *cobra.Command, name string) bool {
	plaintext := grpcCompletionBool(command, grpcPlaintextFlagName)
	insecure := grpcCompletionBool(command, grpcInsecureFlagName)
	ca := grpcCompletionString(command, tlsconfig.CAFlagName)
	systemCA := grpcCompletionBool(command, tlsconfig.SystemCAFlagName)
	switch name {
	case grpcPlaintextFlagName:
		return ca == "" && !systemCA && !insecure &&
			grpcCompletionString(command, tlsconfig.ServerNameFlagName) == "" &&
			grpcCompletionString(command, tlsconfig.CertFlagName) == "" && grpcCompletionString(command, tlsconfig.KeyFlagName) == ""
	case grpcInsecureFlagName:
		return !plaintext && ca == "" && !systemCA
	case tlsconfig.SystemCAFlagName, tlsconfig.CAFlagName:
		return !plaintext && !insecure
	default:
		return !plaintext
	}
}

func completeGRPC(
	command *cobra.Command,
	args []string,
	prefix string,
	options *grpcOptions,
	kind grpcCompletionKind,
) ([]string, cobra.ShellCompDirective) {
	directive := cobra.ShellCompDirectiveNoFileComp
	if kind == grpcCompleteSelector && !strings.Contains(prefix, "/") {
		directive |= cobra.ShellCompDirectiveNoSpace
	}
	if tlsconfig.UsesStdin(command) || !validGRPCCompletionEndpoint(args[0]) {
		return nil, directive
	}

	ctx, cancel := context.WithTimeout(command.Context(), grpcCompletionTimeout)
	defer cancel()
	schema, connection, reflectionCtx := grpcCompletionSchema(ctx, command, args[0], options)
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

func grpcCompletionSchema(
	ctx context.Context,
	command *cobra.Command,
	endpoint string,
	options *grpcOptions,
) (*grpcSchema, *grpc.ClientConn, context.Context) {
	if validateGRPCTLSOptionCombinations(options) != nil || tlsconfig.ValidateArtifactSources(command, !options.plaintext, false, ErrInvalidOptions) != nil {
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
	if err != nil || !regularGRPCCompletionCredentialFiles(options) {
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

func regularGRPCCompletionCredentialFiles(options *grpcOptions) bool {
	for _, path := range []string{options.ca, options.cert, options.key} {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
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
	case grpcCompleteService:
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

func validGRPCCompletionEndpoint(endpoint string) bool {
	host, portText, err := net.SplitHostPort(endpoint)
	invalidHost := strings.IndexFunc(host, func(char rune) bool {
		return unicode.IsSpace(char) || char < ' ' || char == 127
	}) >= 0
	if err != nil || host == "" || invalidHost {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}
