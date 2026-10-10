package crpc

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/connectrpc"
	"github.com/sosheskaz/swys/internal/contextio"
	"github.com/sosheskaz/swys/internal/protoschema"
)

type targetSelection struct {
	base      *url.URL
	endpoint  connectrpc.Endpoint
	discovery bool
}

func selectTarget(args []string, settings *options) (targetSelection, error) {
	explicit := settings.list != "" || settings.describe != ""
	if len(args) == 0 {
		if settings.protoset == "" {
			return targetSelection{}, fmt.Errorf("%w: provide a URL, or --protoset for offline discovery", ErrInvalidFlags)
		}
		return targetSelection{discovery: true}, nil
	}
	base, err := connectrpc.ParseBase(args[0])
	if err != nil {
		return targetSelection{}, err
	}
	if explicit && len(args) > 1 {
		return targetSelection{}, fmt.Errorf("%w: discovery does not take a positional method", ErrInvalidFlags)
	}
	if len(args) == 1 && (explicit || base.Path == "" || strings.HasSuffix(base.EscapedPath(), "/")) {
		return targetSelection{base: base, discovery: true}, nil
	}
	method := ""
	if len(args) == 2 {
		method = args[1]
	}
	endpoint, err := connectrpc.ParseEndpoint(args[0], method)
	if err != nil {
		return targetSelection{}, err
	}
	return targetSelection{endpoint: endpoint, base: endpoint.BaseURL()}, nil
}

func validateSchemaOptions(cmd *cobra.Command, settings *options) error {
	if settings.protoset != "" && settings.reflectSchema {
		return fmt.Errorf("%w: --protoset and --reflect are mutually exclusive", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("protoset") && (settings.protoset == "" || settings.protoset == "-") {
		return fmt.Errorf("%w: --protoset requires a file path", ErrInvalidFlags)
	}
	if cmd.Flags().Changed("list") && settings.list == "" || cmd.Flags().Changed("describe") && settings.describe == "" {
		return fmt.Errorf("%w: discovery requires a nonempty symbol", ErrInvalidFlags)
	}
	if settings.list != "" && settings.describe != "" {
		return fmt.Errorf("%w: --list and --describe are mutually exclusive", ErrInvalidFlags)
	}
	if settings.discovery {
		for _, name := range []string{"data", "input", "input-encoding", "stdin", "stream", "wait", "timeout", "max-message-size"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("%w: --%s applies only to invocation", ErrInvalidFlags, name)
			}
		}
	}
	return nil
}

func loadSchema(
	cmd *cobra.Command, settings *options, target targetSelection, connection connectrpc.Options, headers *connect.Header,
) (*protoschema.Schema, error) {
	if settings.protoset != "" {
		return loadProtoset(cmd, settings.protoset)
	}
	if !settings.reflectSchema && !target.discovery {
		return nil, nil //nolint:nilnil // no explicit schema source means schema-free invocation
	}
	symbol := settings.describe
	if settings.list != "" {
		symbol = settings.list
	}
	if !target.discovery {
		symbol, _, _ = strings.Cut(strings.TrimPrefix(target.endpoint.Procedure, "/"), "/")
	}
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.reflectionTimeout)
	defer cancel()
	ctx, call := callContext(ctx, headers)
	schema, err := connectrpc.Reflect(ctx, target.base, connection, symbol)
	if settings.verbose {
		err = errors.Join(err, writeDiagnostics(ctx, cmd.ErrOrStderr(), call, err))
	}
	if err != nil {
		return nil, fmt.Errorf("discover Connect schema: %w", safeError(err))
	}
	return schema, nil
}

func loadProtoset(cmd *cobra.Command, path string) (*protoschema.Schema, error) {
	file, err := contextio.OpenFile(cmd.Context(), func() (*os.File, error) { return os.Open(path) }) //nolint:gosec // user-selected descriptor path
	if err != nil {
		return nil, fmt.Errorf("open protoset: %w", err)
	}
	input, err := contextio.NewOwnedFileReader(cmd.Context(), file)
	if err != nil {
		return nil, fmt.Errorf("prepare protoset: %w", err)
	}
	set, readErr := protoschema.Read(input)
	if err := errors.Join(readErr, input.Close()); err != nil {
		return nil, err
	}
	return protoschema.New(set)
}

func resolveMethod(
	cmd *cobra.Command, settings *options, schema *protoschema.Schema, selector string, requested connect.StreamType,
) (protoreflect.MethodDescriptor, connect.StreamType, error) {
	if schema == nil {
		return nil, requested, nil
	}
	method, err := schema.Method(selector)
	if err != nil {
		return nil, 0, err
	}
	kind := connect.StreamTypeUnary
	if method.IsStreamingClient() {
		kind |= connect.StreamTypeClient
	}
	if method.IsStreamingServer() {
		kind |= connect.StreamTypeServer
	}
	if cmd.Flags().Changed("stream") && requested != kind {
		return nil, 0, fmt.Errorf("%w: --stream %s conflicts with the method's %s cardinality", ErrInvalidFlags, settings.stream, streamName(kind))
	}
	return method, kind, nil
}

func streamName(kind connect.StreamType) string {
	switch kind {
	case connect.StreamTypeClient:
		return streamClient
	case connect.StreamTypeServer:
		return streamServer
	case connect.StreamTypeBidi:
		return streamBidi
	case connect.StreamTypeUnary:
		return streamUnary
	default:
		return "unknown"
	}
}

func validateMessage(data []byte, method protoreflect.MethodDescriptor, schema *protoschema.Schema) (jsontext.Value, error) {
	value, err := connectrpc.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	if method != nil {
		message := dynamicpb.NewMessage(method.Input())
		if err := (protojson.UnmarshalOptions{Resolver: dynamicpb.NewTypes(schema.Files)}).Unmarshal(data, message); err != nil {
			return nil, fmt.Errorf("validate request for %s: %w", method.FullName(), err)
		}
	}
	return value, nil
}

func renderDiscovery(schema *protoschema.Schema, settings *options) ([]byte, error) {
	if settings.describe != "" {
		return renderDescriptor(schema, settings.describe, settings.format)
	}
	values, err := discoveryValues(schema, settings.list)
	if err != nil {
		return nil, err
	}
	if settings.format == formatJSON {
		data, err := json.Marshal(values)
		if err != nil {
			return nil, fmt.Errorf("format discovery JSON: %w", err)
		}
		return append(data, '\n'), nil
	}
	if len(values) == 0 {
		return []byte{}, nil
	}
	return []byte(strings.Join(values, "\n") + "\n"), nil
}

func discoveryValues(schema *protoschema.Schema, list string) ([]string, error) {
	if list == "" {
		return schema.Services, nil
	}
	descriptor, err := schema.Files.FindDescriptorByName(protoreflect.FullName(list))
	if err != nil {
		return nil, fmt.Errorf("find service %q: %w", list, err)
	}
	service, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a service", protoschema.ErrSymbol, list)
	}
	values := make([]string, service.Methods().Len())
	for i := range values {
		values[i] = string(service.Methods().Get(i).Name())
	}
	return values, nil
}

func renderDescriptor(schema *protoschema.Schema, symbol, format string) ([]byte, error) {
	descriptor, err := schema.Files.FindDescriptorByName(protoreflect.FullName(symbol))
	if err != nil {
		return nil, fmt.Errorf("find protobuf symbol %q: %w", symbol, err)
	}
	message, err := protoschema.DescriptorProto(descriptor)
	if err != nil {
		return nil, err
	}
	if format == formatJSON {
		data, err := (protojson.MarshalOptions{Multiline: true, Indent: "  "}).Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("format descriptor JSON: %w", err)
		}
		return append(data, '\n'), nil
	}
	return []byte(prototext.Format(message)), nil
}
