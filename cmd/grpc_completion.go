package cmd

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
)

const grpcCompletionTimeout = 2 * time.Second

type grpcCompletionKind uint8

const (
	grpcCompleteSelector grpcCompletionKind = iota
	grpcCompleteService
	grpcCompleteSymbol
)

func registerGRPCCompletion(command *cobra.Command, options *grpcOptions) {
	command.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeGRPC(cmd, args, prefix, options, grpcCompleteSelector)
	}
	for name, kind := range map[string]grpcCompletionKind{
		"list":     grpcCompleteService,
		"describe": grpcCompleteSymbol,
	} {
		completionKind := kind
		if err := command.RegisterFlagCompletionFunc(name, func(
			cmd *cobra.Command,
			args []string,
			prefix string,
		) ([]string, cobra.ShellCompDirective) {
			if len(args) != 1 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeGRPC(cmd, args, prefix, options, completionKind)
		}); err != nil {
			panic(err)
		}
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
	if !validGRPCCompletionEndpoint(args[0]) {
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
	if validateGRPCTLSOptionCombinations(options) != nil {
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
	if grpcCompletionService(schema.services, prefix, kind) == "" {
		return sortedUniqueGRPCCompletions(values)
	}
	separator := "/"
	if kind == grpcCompleteSymbol {
		separator = "."
	}
	schema.files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		for serviceIndex := range file.Services().Len() {
			service := file.Services().Get(serviceIndex)
			for methodIndex := range service.Methods().Len() {
				method := service.Methods().Get(methodIndex)
				if kind == grpcCompleteSelector && (method.IsStreamingClient() || method.IsStreamingServer()) {
					continue
				}
				candidate := string(service.FullName()) + separator + string(method.Name())
				if strings.HasPrefix(candidate, prefix) {
					values = append(values, candidate)
				}
			}
		}
		return true
	})
	return sortedUniqueGRPCCompletions(values)
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
