package grpc

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/contextio"
)

//go:embed guides
var grpcGuideFiles embed.FS

const (
	grpcRequestShape       = "grpc-request"
	grpcDefaultMessageSize = 16 << 20
	grpcDescriptorBytes    = 16 << 20
	grpcDescriptorFiles    = 1024
	grpcDescriptorDepth    = 100
	grpcReflectionOverhead = 64 << 10
)

type grpcOptions struct { //nolint:govet // flag registration is clearer when related values stay grouped
	list           string
	describe       string
	protoset       string
	data           string
	headers        []string
	format         string
	ca             string
	cert           string
	key            string
	serverName     string
	timeout        time.Duration
	maxMessageSize int
	plaintext      bool
	systemCA       bool
	insecure       bool
	verbose        bool
}

type grpcPreparation struct {
	output      []byte
	diagnostics []byte
}

type grpcCallDetails struct {
	header  metadata.MD
	trailer metadata.MD
	peer    peer.Peer
	status  *status.Status
}

type grpcStatusDiagnosticError struct { //nolint:govet // field names make the diagnostic wrapper's intent explicit
	operation string
	status    *status.Status
	cause     error
}

type grpcTLSCapture struct { //nolint:govet // mutex and captured interface form one small synchronized state
	mu       sync.Mutex
	authInfo credentials.AuthInfo
}

func (capture *grpcTLSCapture) store(authInfo credentials.AuthInfo) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.authInfo = authInfo
}

func (capture *grpcTLSCapture) load() credentials.AuthInfo {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.authInfo
}

type grpcCapturingCredentials struct {
	credentials.TransportCredentials
	capture *grpcTLSCapture
}

// ClientHandshake records the peer authentication state returned by the underlying credentials.
func (creds *grpcCapturingCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	rawConnection net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	connection, authInfo, err := creds.TransportCredentials.ClientHandshake(ctx, authority, rawConnection)
	if err != nil {
		return connection, authInfo, fmt.Errorf("perform gRPC client handshake: %w", err)
	}
	creds.capture.store(authInfo)
	return connection, authInfo, nil
}

// Clone copies the underlying credentials while retaining the connection-state capture.
func (creds *grpcCapturingCredentials) Clone() credentials.TransportCredentials {
	return &grpcCapturingCredentials{
		TransportCredentials: creds.TransportCredentials.Clone(),
		capture:              creds.capture,
	}
}

func (err *grpcStatusDiagnosticError) Error() string {
	return fmt.Sprintf(
		"%s: %s: %s",
		err.operation,
		err.status.Code(),
		formatGRPCStatusMessage(err.status.Message()),
	)
}

func (err *grpcStatusDiagnosticError) Unwrap() error { return err.cause }

// GRPCStatus preserves the original status code without exposing its unescaped message.
func (err *grpcStatusDiagnosticError) GRPCStatus() *status.Status { return err.status }

const (
	grpcFormatText = "text"
	grpcFormatJSON = "json"
)

// NewCommand constructs the gRPC command and registers its I/O behavior.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	options := &grpcOptions{}
	var prepared *grpcPreparation
	var pending *grpcPreparation
	command := &cobra.Command{
		Use:   "grpc HOST:PORT [SERVICE/METHOD]",
		Short: "Discover gRPC schemas and invoke unary methods",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if prepared == nil {
				return commandio.ErrPreparedOutputUnavailable
			}
			if len(prepared.diagnostics) != 0 {
				if _, err := cmd.ErrOrStderr().Write(prepared.diagnostics); err != nil {
					return fmt.Errorf("write gRPC diagnostics: %w", err)
				}
			}
			output, writer, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			if _, err := writer.Write(output); err != nil {
				return fmt.Errorf("write gRPC output: %w", err)
			}
			return nil
		},
	}
	lifecycle.Register(command, commandio.Behavior{
		BeforeIO: func(cmd *cobra.Command, args []string) (func(error) error, error) {
			prepared, pending = nil, nil
			result, err := prepareGRPC(cmd, args, options)
			if err != nil {
				return nil, err
			}
			pending = result
			return func(configureErr error) error {
				if configureErr != nil {
					pending = nil
					return configureErr
				}
				prepared = result
				commandio.AppendCleanup(cmd, func() { prepared, pending = nil, nil })
				return nil
			}, nil
		},
		InputPrepared:         true,
		ClearInheritedStreams: true,
		PreparesOutput:        func(*cobra.Command) bool { return true },
		Prepare: func(*cobra.Command, io.Reader) ([]byte, error) {
			if pending == nil {
				return nil, commandio.ErrPreparedOutputUnavailable
			}
			return pending.output, nil
		},
	})
	commandio.AddShape(command, grpcRequestShape)
	commandio.AddShape(command, "structured-output")
	commandio.AddShape(command, "network")
	flags := command.PersistentFlags()
	flags.StringVar(&options.list, "list", "", "list methods in a service")
	flags.StringVar(&options.describe, "describe", "", "describe a protobuf symbol")
	flags.StringVar(&options.protoset, "protoset", "", "read descriptors from a FileDescriptorSet instead of reflection")
	flags.StringVarP(&options.data, "data", "d", "", "literal protobuf JSON request")
	flags.StringArrayVarP(&options.headers, "header", "H", nil, "request metadata (name: value); repeatable")
	flags.StringVarP(&options.format, commandio.FormatFlagName, "f", grpcFormatText, "discovery output format (text, json)")
	flags.DurationVar(&options.timeout, "timeout", commandio.DefaultNetworkTimeout, "overall connection, reflection, and invocation timeout (0 disables)")
	flags.IntVar(&options.maxMessageSize, "max-message-size", grpcDefaultMessageSize, "maximum sent and received protobuf message size in bytes")
	flags.BoolVar(&options.plaintext, "plaintext", false, "use plaintext HTTP/2 instead of TLS")
	flags.StringVar(&options.ca, tlsconfig.CAFlagName, "", "custom CA certificate bundle PEM path")
	flags.BoolVar(&options.systemCA, "system-ca", false, "include system roots with --ca")
	flags.StringVar(&options.serverName, "servername", "", "override TLS SNI and verification name")
	flags.StringVar(&options.cert, tlsconfig.CertFlagName, "", "client certificate chain PEM path")
	flags.StringVar(&options.key, tlsconfig.KeyFlagName, "", "client private key path")
	flags.BoolVar(&options.insecure, "insecure", false, "disable TLS certificate and hostname verification")
	flags.BoolVarP(&options.verbose, "verbose", "v", false, "write status, metadata, and TLS details to stderr")
	registerGRPCCompletion(command, options)
	commandio.RegisterFlagCompletion(command, commandio.FormatFlagName, func() []string { return []string{grpcFormatText, grpcFormatJSON} })
	for _, name := range []string{tlsconfig.CAFlagName, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, "protoset"} {
		if err := command.MarkPersistentFlagFilename(name); err != nil {
			panic(err)
		}
	}
	if err := help.RegisterGuides(command, grpcGuideFiles); err != nil {
		panic(err)
	}
	return command
}

//nolint:gocognit,gocyclo,nestif // ordered state contract remains visible
func prepareGRPC(cmd *cobra.Command, args []string, options *grpcOptions) (*grpcPreparation, error) {
	selector := ""
	selectorPresent := len(args) == 2
	if len(args) == 2 {
		selector = args[1]
	}
	if err := validateGRPCOptions(cmd, args[0], selector, selectorPresent, options); err != nil {
		return nil, err
	}
	md, err := parseGRPCMetadata(options.headers)
	if err != nil {
		return nil, err
	}
	commandCtx := cmd.Context()
	var requestData []byte
	if selector != "" {
		requestData, err = readGRPCRequest(commandCtx, cmd, options)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := grpcOverallContext(commandCtx, options.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, md)

	var conn *grpc.ClientConn
	var tlsCapture *grpcTLSCapture
	var schema *grpcSchema
	var reflectionDetails grpcCallDetails
	if cmd.Flags().Changed("protoset") {
		schema, err = loadGRPCProtoset(options.protoset)
	} else {
		conn, tlsCapture, err = dialGRPC(cmd, args[0], options)
		if err == nil {
			defer conn.Close() //nolint:errcheck // command is complete and the response is already prepared
			schema, reflectionDetails, err = reflectGRPCSchema(ctx, conn, selector, options.list, options.describe)
			if options.verbose && err != nil {
				applyGRPCTLSCapture(&reflectionDetails, tlsCapture)
				if diagnosticErr := writeGRPCDiagnostics(cmd.ErrOrStderr(), options, reflectionDetails); diagnosticErr != nil {
					return nil, errors.Join(grpcStatusError("discover gRPC schema", err), diagnosticErr)
				}
			}
		}
	}
	if err != nil {
		return nil, grpcStatusError("discover gRPC schema", err)
	}

	if selector == "" {
		output, renderErr := schema.renderDiscovery(options.list, options.describe, options.format)
		if renderErr != nil {
			return nil, renderErr
		}
		result := &grpcPreparation{output: output}
		if options.verbose {
			applyGRPCTLSCapture(&reflectionDetails, tlsCapture)
			if reflectionDetails.status == nil {
				reflectionDetails.status = status.New(codes.OK, "")
			}
			result.diagnostics = grpcDiagnostics(options, reflectionDetails)
		}
		return result, nil
	}
	if conn == nil {
		conn, tlsCapture, err = dialGRPC(cmd, args[0], options)
		if err != nil {
			return nil, err
		}
		defer conn.Close() //nolint:errcheck // command is complete and the response is already prepared
	}
	method, err := schema.findMethod(selector)
	if err != nil {
		return nil, err
	}
	if method.IsStreamingClient() || method.IsStreamingServer() {
		return nil, fmt.Errorf("%w: method %q is streaming; only unary invocation is supported", errUnsupportedGRPC, selector)
	}
	types := dynamicpb.NewTypes(schema.files)
	request := dynamicpb.NewMessage(method.Input())
	if len(requestData) == 0 {
		requestData = []byte("{}")
	}
	if err := (protojson.UnmarshalOptions{Resolver: types, DiscardUnknown: false}).Unmarshal(requestData, request); err != nil {
		return nil, fmt.Errorf("parse protobuf JSON request: %w", err)
	}
	if proto.Size(request) > options.maxMessageSize {
		return nil, fmt.Errorf(
			"%w: request is %d bytes, maximum is %d",
			ErrMessageLimit,
			proto.Size(request),
			options.maxMessageSize,
		)
	}
	response := dynamicpb.NewMessage(method.Output())
	var header, trailer metadata.MD
	var remotePeer peer.Peer
	err = conn.Invoke(
		ctx,
		"/"+selector,
		request,
		response,
		grpc.Header(&header),
		grpc.Trailer(&trailer),
		grpc.Peer(&remotePeer),
		grpc.MaxCallSendMsgSize(options.maxMessageSize),
		grpc.MaxCallRecvMsgSize(options.maxMessageSize),
	)
	details := grpcCallDetails{header: header, trailer: trailer, peer: remotePeer, status: status.Convert(err)}
	applyGRPCTLSCapture(&details, tlsCapture)
	if err != nil {
		if options.verbose {
			if diagnosticErr := writeGRPCDiagnostics(cmd.ErrOrStderr(), options, details); diagnosticErr != nil {
				return nil, errors.Join(grpcStatusError("invoke gRPC method", err), diagnosticErr)
			}
		}
		return nil, grpcStatusError("invoke gRPC method", err)
	}
	output, err := (protojson.MarshalOptions{Resolver: types}).Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("serialize protobuf JSON response: %w", err)
	}
	output = append(output, '\n')
	result := &grpcPreparation{output: output}
	if options.verbose {
		result.diagnostics = grpcDiagnostics(options, details)
	}
	return result, nil
}

//nolint:gocognit,gocyclo // ordered local validation must complete before any side effect
func validateGRPCOptions(cmd *cobra.Command, endpoint, selector string, selectorPresent bool, options *grpcOptions) error {
	host, portText, err := net.SplitHostPort(endpoint)
	invalidHostCharacter := func(char rune) bool {
		return unicode.IsSpace(char) || char < ' ' || char == 127
	}
	if err != nil || host == "" || strings.IndexFunc(host, invalidHostCharacter) >= 0 {
		return fmt.Errorf("%w: endpoint %q requires a host and numeric port", ErrInvalidOptions, endpoint)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: endpoint %q port must be from 1 to 65535", ErrInvalidOptions, endpoint)
	}
	listChanged := cmd.Flags().Changed("list")
	describeChanged := cmd.Flags().Changed("describe")
	if listChanged && options.list == "" {
		return fmt.Errorf("%w: --list must not be empty", ErrInvalidOptions)
	}
	if describeChanged && options.describe == "" {
		return fmt.Errorf("%w: --describe must not be empty", ErrInvalidOptions)
	}
	if selectorPresent && selector == "" {
		return fmt.Errorf("%w: method selector must not be empty", ErrInvalidOptions)
	}
	if cmd.Flags().Changed("protoset") && options.protoset == "" {
		return fmt.Errorf("%w: --protoset must not be empty", ErrInvalidOptions)
	}
	if !selectorPresent && (cmd.Flags().Changed("data") || cmd.Flags().Changed("input")) {
		return fmt.Errorf("%w: --data and --input require a method selector", ErrInvalidOptions)
	}
	selectors := 0
	for _, selected := range []bool{selectorPresent, listChanged, describeChanged} {
		if selected {
			selectors++
		}
	}
	if selectors > 1 {
		return fmt.Errorf("%w: method, --list, and --describe are mutually exclusive", ErrInvalidOptions)
	}
	if selector != "" && !validGRPCMethodSelector(selector) {
		return fmt.Errorf("%w: method selector %q must be SERVICE/METHOD", ErrInvalidOptions, selector)
	}
	if options.timeout < 0 {
		return fmt.Errorf("%w: --timeout cannot be negative", ErrInvalidOptions)
	}
	if options.maxMessageSize <= 0 || options.maxMessageSize > int(^uint(0)>>1)/4 {
		return fmt.Errorf("%w: --max-message-size must be positive and allow a safe JSON limit", ErrInvalidOptions)
	}
	if options.format != grpcFormatText && options.format != grpcFormatJSON {
		return fmt.Errorf("%w: --format must be text or json", ErrInvalidOptions)
	}
	if cmd.Flags().Changed("data") && cmd.Flags().Changed("input") {
		return fmt.Errorf("%w: --data and --input are mutually exclusive", ErrInvalidOptions)
	}
	if err := validateGRPCTLSOptionCombinations(options); err != nil {
		return err
	}
	if err := certinput.ValidatePaths(cmd, tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName); err != nil {
		return err
	}
	identityInput := ""
	if cmd.Flags().Changed("input") {
		input, err := cmd.Flags().GetString("input")
		if err != nil || input == "" {
			return fmt.Errorf("%w: --input requires a path or -", ErrInvalidOptions)
		}
		if input != "-" {
			identityInput = input
		}
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("read output flag: %w", err)
	}
	if err := commandio.RejectSameFile(identityInput, output); err != nil {
		return err
	}
	return commandio.RejectSameFile(options.protoset, output)
}

func validateGRPCTLSOptionCombinations(options *grpcOptions) error {
	if options.plaintext && (options.ca != "" || options.systemCA || options.serverName != "" || options.cert != "" || options.key != "" || options.insecure) {
		return fmt.Errorf("%w: --plaintext conflicts with TLS flags", ErrInvalidOptions)
	}
	if (options.cert == "") != (options.key == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", ErrInvalidOptions)
	}
	if options.systemCA && options.ca == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", ErrInvalidOptions)
	}
	if options.insecure && (options.ca != "" || options.systemCA) {
		return fmt.Errorf("%w: --insecure conflicts with --ca and --system-ca", ErrInvalidOptions)
	}
	return nil
}

func validGRPCMethodSelector(selector string) bool {
	service, method, ok := strings.Cut(selector, "/")
	return ok && service != "" && method != "" && !strings.Contains(method, "/") && strings.IndexFunc(selector, unicode.IsSpace) < 0
}

func grpcOverallContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

//nolint:gocyclo // one pass keeps validation and decoded values inseparable
func parseGRPCMetadata(values []string) (metadata.MD, error) {
	result := metadata.MD{}
	for _, value := range values {
		key, content, ok := strings.Cut(value, ":")
		if !ok || key == "" || key != strings.ToLower(key) {
			return nil, fmt.Errorf("%w %q", ErrInvalidMetadata, value)
		}
		for _, char := range key {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.", char) {
				continue
			}
			return nil, fmt.Errorf("%w key %q", ErrInvalidMetadata, key)
		}
		if reservedGRPCMetadataKey(key) {
			return nil, fmt.Errorf("%w: reserved key %q", ErrInvalidMetadata, key)
		}
		for _, char := range content {
			if char < ' ' || char > '~' {
				return nil, fmt.Errorf("%w: non-printable ASCII value in %q", ErrInvalidMetadata, key)
			}
		}
		content = strings.Trim(content, " ")
		if strings.HasSuffix(key, "-bin") {
			decoded, err := base64.StdEncoding.DecodeString(content)
			if err != nil {
				return nil, fmt.Errorf("decode binary gRPC metadata %q: %w", key, err)
			}
			content = string(decoded)
		}
		result.Append(key, content)
	}
	return result, nil
}

func reservedGRPCMetadataKey(key string) bool {
	if strings.HasPrefix(key, "grpc-") {
		return true
	}
	switch key {
	case "connection", "content-type", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "upgrade", "user-agent":
		return true
	default:
		return false
	}
}

func dialGRPC(cmd *cobra.Command, endpoint string, options *grpcOptions) (*grpc.ClientConn, *grpcTLSCapture, error) {
	transport, err := grpcTransportCredentials(cmd, endpoint, options)
	if err != nil {
		return nil, nil, err
	}
	var capture *grpcTLSCapture
	if !options.plaintext {
		capture = &grpcTLSCapture{}
		transport = &grpcCapturingCredentials{TransportCredentials: transport, capture: capture}
	}
	target := (&url.URL{Scheme: "dns", Path: "/" + endpoint}).String()
	connection, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(transport),
		grpc.WithDisableServiceConfig(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create gRPC client: %w", err)
	}
	return connection, capture, nil
}

func applyGRPCTLSCapture(details *grpcCallDetails, capture *grpcTLSCapture) {
	if details.peer.AuthInfo == nil && capture != nil {
		details.peer.AuthInfo = capture.load()
	}
}

func grpcTransportCredentials(cmd *cobra.Command, endpoint string, options *grpcOptions) (credentials.TransportCredentials, error) {
	if options.plaintext {
		return insecure.NewCredentials(), nil
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse gRPC endpoint %q: %w", endpoint, err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: options.serverName}
	config.InsecureSkipVerify = options.insecure
	if config.ServerName == "" {
		config.ServerName = host
	}
	if err := tlsconfig.AddRootCAs(cmd, config); err != nil {
		return nil, err
	}
	identity, exists, err := tlsconfig.ClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if exists {
		config.Certificates = []tls.Certificate{identity}
	}
	return credentials.NewTLS(config), nil
}

func readGRPCRequest(ctx context.Context, cmd *cobra.Command, options *grpcOptions) ([]byte, error) {
	limit := int64(options.maxMessageSize) * 4
	if cmd.Flags().Changed("data") {
		if int64(len(options.data)) > limit {
			return nil, fmt.Errorf("%w: request JSON exceeds %d bytes", ErrMessageLimit, limit)
		}
		return []byte(options.data), nil
	}
	reader := cmd.InOrStdin()
	if cmd.Flags().Changed("input") {
		path, err := cmd.Flags().GetString("input")
		if err != nil {
			return nil, fmt.Errorf("read input flag: %w", err)
		}
		if path != "-" {
			return readGRPCRequestFile(ctx, path, limit)
		}
	} else if commandio.InputIsTerminal(reader) {
		return []byte("{}"), nil
	}
	return readGRPCRequestReader(ctx, reader, limit)
}

func readGRPCRequestReader(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read gRPC request JSON: %w", context.Cause(ctx))
	}
	readCtx, cancelRead := context.WithCancelCause(ctx)
	defer cancelRead(nil)
	data, err := io.ReadAll(io.LimitReader(contextio.NewReader(readCtx, reader), limit+1))
	if err != nil {
		return nil, fmt.Errorf("read gRPC request JSON: %w", err)
	}
	return validateGRPCRequestSize(data, limit)
}

func readGRPCRequestFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	file, err := commandio.OpenInput(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read gRPC request JSON: %w", err)
	}
	reader, err := contextio.NewOwnedFileReader(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("read gRPC request JSON: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
	closeErr := reader.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		readErr = context.Cause(ctx)
	} else if readErr == nil && closeErr != nil {
		readErr = fmt.Errorf("close gRPC input %q: %w", path, closeErr)
	}
	if readErr != nil {
		return nil, fmt.Errorf("read gRPC request JSON: %w", readErr)
	}
	return validateGRPCRequestSize(data, limit)
}

func validateGRPCRequestSize(data []byte, limit int64) ([]byte, error) {
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: request JSON exceeds %d bytes", ErrMessageLimit, limit)
	}
	return data, nil
}

type grpcSchema struct {
	files    *protoregistry.Files
	fileSet  *descriptorpb.FileDescriptorSet
	services []string
}

func newGRPCSchema(set *descriptorpb.FileDescriptorSet) (*grpcSchema, error) {
	if err := validateGRPCDescriptorSet(set); err != nil {
		return nil, err
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("resolve gRPC descriptors: %w", err)
	}
	services := []string{}
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		for index := range file.Services().Len() {
			services = append(services, string(file.Services().Get(index).FullName()))
		}
		return true
	})
	sort.Strings(services)
	return &grpcSchema{files: files, fileSet: set, services: services}, nil
}

func validateGRPCDescriptorSet(set *descriptorpb.FileDescriptorSet) error {
	if len(set.File) > grpcDescriptorFiles {
		return fmt.Errorf("%w: set has %d files, maximum is %d", errGRPCDescriptorLimit, len(set.File), grpcDescriptorFiles)
	}
	total := 0
	type depthItem struct {
		message *descriptorpb.DescriptorProto
		depth   int
	}
	for _, file := range set.File {
		total += proto.Size(file)
		if total > grpcDescriptorBytes {
			return fmt.Errorf("%w: descriptors exceed %d bytes", errGRPCDescriptorLimit, grpcDescriptorBytes)
		}
		stack := make([]depthItem, 0, len(file.GetMessageType()))
		for _, message := range file.GetMessageType() {
			stack = append(stack, depthItem{message: message, depth: 1})
		}
		for len(stack) != 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current.depth > grpcDescriptorDepth {
				return fmt.Errorf("%w: message nesting exceeds %d", errGRPCDescriptorLimit, grpcDescriptorDepth)
			}
			for _, nested := range current.message.GetNestedType() {
				stack = append(stack, depthItem{message: nested, depth: current.depth + 1})
			}
		}
	}
	return nil
}

func loadGRPCProtoset(path string) (*grpcSchema, error) {
	file, err := os.Open(path) //nolint:gosec // user-selected descriptor path
	if err != nil {
		return nil, fmt.Errorf("open gRPC protoset %q: %w", path, err)
	}
	defer file.Close() //nolint:errcheck // read/unmarshal result is authoritative
	data, err := io.ReadAll(io.LimitReader(file, grpcDescriptorBytes*2+1))
	if err != nil {
		return nil, fmt.Errorf("read gRPC protoset: %w", err)
	}
	if len(data) > grpcDescriptorBytes*2 {
		return nil, fmt.Errorf("%w: protoset file is too large", errGRPCDescriptorLimit)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("parse gRPC protoset: %w", err)
	}
	return newGRPCSchema(set)
}

func (schema *grpcSchema) findMethod(selector string) (protoreflect.MethodDescriptor, error) {
	serviceName, methodName, _ := strings.Cut(selector, "/")
	descriptor, err := schema.files.FindDescriptorByName(protoreflect.FullName(serviceName))
	if err != nil {
		return nil, fmt.Errorf("find gRPC service %q: %w", serviceName, err)
	}
	service, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%w: gRPC symbol %q is not a service", errUnsupportedGRPC, serviceName)
	}
	method := service.Methods().ByName(protoreflect.Name(methodName))
	if method == nil {
		return nil, fmt.Errorf("%w: gRPC service %q has no method %q", errUnsupportedGRPC, serviceName, methodName)
	}
	return method, nil
}

//nolint:nestif // selector-specific rendering is intentionally kept at the consumer boundary
func (schema *grpcSchema) renderDiscovery(list, describe, format string) ([]byte, error) {
	if list != "" {
		descriptor, err := schema.files.FindDescriptorByName(protoreflect.FullName(list))
		if err != nil {
			return nil, fmt.Errorf("find gRPC service %q: %w", list, err)
		}
		service, ok := descriptor.(protoreflect.ServiceDescriptor)
		if !ok {
			return nil, fmt.Errorf("%w: gRPC symbol %q is not a service", errUnsupportedGRPC, list)
		}
		methods := make([]string, service.Methods().Len())
		for index := range methods {
			methods[index] = string(service.Methods().Get(index).Name())
		}
		return grpcDiscoveryList(methods, format)
	}
	if describe != "" {
		descriptor, err := schema.files.FindDescriptorByName(protoreflect.FullName(describe))
		if err != nil {
			return nil, fmt.Errorf("find gRPC symbol %q: %w", describe, err)
		}
		protoDescriptor, err := grpcDescriptorProto(descriptor)
		if err != nil {
			return nil, err
		}
		if format == grpcFormatJSON {
			data, err := (protojson.MarshalOptions{Multiline: true, Indent: "  "}).Marshal(protoDescriptor)
			if err != nil {
				return nil, fmt.Errorf("serialize gRPC descriptor JSON: %w", err)
			}
			return append(data, '\n'), nil
		}
		return []byte(prototext.Format(protoDescriptor)), nil
	}
	return grpcDiscoveryList(schema.services, format)
}

func grpcDescriptorProto(descriptor protoreflect.Descriptor) (proto.Message, error) {
	switch value := descriptor.(type) {
	case protoreflect.MessageDescriptor:
		return protodesc.ToDescriptorProto(value), nil
	case protoreflect.FieldDescriptor:
		return protodesc.ToFieldDescriptorProto(value), nil
	case protoreflect.OneofDescriptor:
		return protodesc.ToOneofDescriptorProto(value), nil
	case protoreflect.EnumDescriptor:
		return protodesc.ToEnumDescriptorProto(value), nil
	case protoreflect.EnumValueDescriptor:
		return protodesc.ToEnumValueDescriptorProto(value), nil
	case protoreflect.ServiceDescriptor:
		return protodesc.ToServiceDescriptorProto(value), nil
	case protoreflect.MethodDescriptor:
		return protodesc.ToMethodDescriptorProto(value), nil
	case protoreflect.FileDescriptor:
		return protodesc.ToFileDescriptorProto(value), nil
	default:
		return nil, fmt.Errorf("%w: descriptor type %T", errUnsupportedGRPC, descriptor)
	}
}

func grpcDiscoveryList(values []string, format string) ([]byte, error) {
	if format == grpcFormatJSON {
		data, err := json.Marshal(values)
		if err != nil {
			return nil, fmt.Errorf("serialize gRPC discovery JSON: %w", err)
		}
		return append(data, '\n'), nil
	}
	if len(values) == 0 {
		return []byte{}, nil
	}
	return []byte(strings.Join(values, "\n") + "\n"), nil
}

func grpcDiagnostics(options *grpcOptions, details grpcCallDetails) []byte {
	var output strings.Builder
	rpcStatus := details.status
	if rpcStatus == nil {
		rpcStatus = status.New(codes.OK, "")
	}
	fmt.Fprintf(&output, "gRPC status: %s", rpcStatus.Code())
	if rpcStatus.Message() != "" {
		fmt.Fprintf(&output, ": %s", formatGRPCStatusMessage(rpcStatus.Message()))
	}
	output.WriteByte('\n')
	writeGRPCMetadataDiagnostics(&output, "header", details.header)
	writeGRPCMetadataDiagnostics(&output, "trailer", details.trailer)
	if options.protoset != "" && details.peer.AuthInfo == nil {
		return []byte(output.String())
	}
	if options.plaintext {
		output.WriteString("gRPC transport: plaintext\n")
		return []byte(output.String())
	}
	tlsState, ok := grpcTLSConnectionState(details.peer.AuthInfo)
	if !ok {
		output.WriteString("gRPC transport: TLS details unavailable\n")
		return []byte(output.String())
	}
	fmt.Fprintf(
		&output,
		"gRPC transport: TLS; version=%s; cipher=%s; server name=%s; verified=%t\n",
		asym.EscapeDiagnosticValue(tls.VersionName(tlsState.Version)),
		asym.EscapeDiagnosticValue(tls.CipherSuiteName(tlsState.CipherSuite)),
		asym.EscapeDiagnosticValue(tlsState.ServerName),
		len(tlsState.VerifiedChains) != 0 && !options.insecure,
	)
	return []byte(output.String())
}

func formatGRPCStatusMessage(message string) string {
	const (
		dataPrefix               = "\ndata: "
		httpStatusMarker         = "unexpected HTTP status code received from server:"
		unexpectedContentType    = "transport: received unexpected content-type "
		missingHTTPContentType   = "malformed header: missing HTTP content-type"
		statusContinuationPrefix = "  | "
	)

	if data := strings.LastIndex(message, dataPrefix); data >= 0 {
		summary, quotedBody := message[:data], message[data+len(dataPrefix):]
		// grpc-go appends non-gRPC response bytes as a double-quoted %q diagnostic.
		doubleQuoted := len(quotedBody) >= 2 && quotedBody[0] == '"' && quotedBody[len(quotedBody)-1] == '"'
		knownContentTypeError := strings.Contains(summary, unexpectedContentType) ||
			strings.Contains(summary, missingHTTPContentType)
		knownSummary := strings.Contains(summary, httpStatusMarker) && knownContentTypeError
		if doubleQuoted && knownSummary {
			if body, err := strconv.Unquote(quotedBody); err == nil {
				message = summary + dataPrefix + body
			}
		}
	}
	return escapeGRPCStatusMessage(message, statusContinuationPrefix)
}

func escapeGRPCStatusMessage(message, continuationPrefix string) string {
	var escaped strings.Builder
	for offset := 0; offset < len(message); {
		if message[offset] == '\r' && offset+1 < len(message) && message[offset+1] == '\n' {
			escaped.WriteByte('\n')
			escaped.WriteString(continuationPrefix)
			offset += 2
			continue
		}
		if message[offset] == '\n' {
			escaped.WriteByte('\n')
			escaped.WriteString(continuationPrefix)
			offset++
			continue
		}
		char, size := utf8.DecodeRuneInString(message[offset:])
		if char == utf8.RuneError && size == 1 {
			const hex = "0123456789abcdef"
			escaped.WriteString(`\x`)
			escaped.WriteByte(hex[message[offset]>>4])
			escaped.WriteByte(hex[message[offset]&0x0f])
			offset++
			continue
		}
		if strconv.IsPrint(char) {
			escaped.WriteRune(char)
		} else {
			quoted := strconv.QuoteRune(char)
			escaped.WriteString(quoted[1 : len(quoted)-1])
		}
		offset += size
	}
	return escaped.String()
}

func grpcTLSConnectionState(authInfo credentials.AuthInfo) (tls.ConnectionState, bool) {
	switch info := authInfo.(type) {
	case credentials.TLSInfo:
		return info.State, true
	case *credentials.TLSInfo:
		return info.State, true
	default:
		return tls.ConnectionState{}, false
	}
}

func writeGRPCMetadataDiagnostics(output *strings.Builder, kind string, values metadata.MD) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range values[key] {
			fmt.Fprintf(
				output,
				"gRPC response %s %s: %s\n",
				kind,
				asym.EscapeDiagnosticValue(key),
				asym.EscapeDiagnosticValue(value),
			)
		}
	}
}

func writeGRPCDiagnostics(output io.Writer, options *grpcOptions, details grpcCallDetails) error {
	if _, err := output.Write(grpcDiagnostics(options, details)); err != nil {
		return fmt.Errorf("write gRPC diagnostics: %w", err)
	}
	return nil
}

func grpcStatusError(operation string, err error) error {
	if rpcStatus, ok := status.FromError(err); ok {
		return &grpcStatusDiagnosticError{operation: operation, status: rpcStatus, cause: err}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// Reflection implementations return serialized FileDescriptorProto values.
// The v1 request is attempted first and alpha is used only for Unimplemented.
func reflectGRPCSchema(
	ctx context.Context,
	conn *grpc.ClientConn,
	selector string,
	list string,
	describe string,
) (*grpcSchema, grpcCallDetails, error) {
	symbol := describe
	if list != "" {
		symbol = list
	}
	if selector != "" {
		symbol, _, _ = strings.Cut(selector, "/")
	}
	set, services, details, err := reflectGRPCV1(ctx, conn, symbol)
	if status.Code(err) == codes.Unimplemented {
		set, services, details, err = reflectGRPCV1Alpha(ctx, conn, symbol)
	}
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			err = errors.Join(contextErr, err)
			details.status = status.FromContextError(contextErr)
		}
		return nil, details, err
	}
	schema, err := newGRPCSchema(set)
	if err != nil {
		return nil, details, err
	}
	if symbol == "" && len(services) != 0 {
		schema.services = services
		sort.Strings(schema.services)
	}
	return schema, details, nil
}

//nolint:dupl // v1 and v1alpha generated stream types cannot share a typed helper
func reflectGRPCV1(
	ctx context.Context,
	conn *grpc.ClientConn,
	symbol string,
) (*descriptorpb.FileDescriptorSet, []string, grpcCallDetails, error) {
	var remotePeer peer.Peer
	stream, err := reflectionv1.NewServerReflectionClient(conn).ServerReflectionInfo(
		ctx,
		grpc.MaxCallRecvMsgSize(grpcDescriptorBytes+grpcReflectionOverhead),
		grpc.Peer(&remotePeer),
	)
	if err != nil {
		return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(err)},
			fmt.Errorf("open gRPC reflection v1 stream: %w", err)
	}
	request := &reflectionv1.ServerReflectionRequest{}
	if symbol == "" {
		request.MessageRequest = &reflectionv1.ServerReflectionRequest_ListServices{ListServices: ""}
	} else {
		request.MessageRequest = &reflectionv1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: symbol}
	}
	sendErr := stream.Send(request)
	if sendErr != nil && !errors.Is(sendErr, io.EOF) {
		return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(sendErr)},
			fmt.Errorf("send gRPC reflection v1 request: %w", sendErr)
	}
	if sendErr == nil {
		if err := stream.CloseSend(); err != nil {
			return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(err)},
				fmt.Errorf("close gRPC reflection v1 request stream: %w", err)
		}
	}
	response, err := stream.Recv()
	details := grpcReflectionDetails(stream.Header, stream.Trailer, remotePeer, err)
	if err != nil {
		return nil, nil, details, fmt.Errorf("receive gRPC reflection v1 response: %w", err)
	}
	if response.GetErrorResponse() != nil {
		err := grpcReflectionError(response.GetErrorResponse().GetErrorCode(), response.GetErrorResponse().GetErrorMessage())
		details.status = status.Convert(err)
		return nil, nil, details, err
	}
	if symbol == "" {
		services := make([]string, 0, len(response.GetListServicesResponse().GetService()))
		for _, service := range response.GetListServicesResponse().GetService() {
			services = append(services, service.GetName())
		}
		return &descriptorpb.FileDescriptorSet{}, services, details, nil
	}
	set, err := decodeGRPCDescriptors(response.GetFileDescriptorResponse().GetFileDescriptorProto())
	return set, nil, details, err
}

//nolint:dupl,staticcheck // compatibility fallback intentionally uses the deprecated official v1alpha protocol
func reflectGRPCV1Alpha(
	ctx context.Context,
	conn *grpc.ClientConn,
	symbol string,
) (*descriptorpb.FileDescriptorSet, []string, grpcCallDetails, error) {
	var remotePeer peer.Peer
	stream, err := reflectionv1alpha.NewServerReflectionClient(conn).ServerReflectionInfo(
		ctx,
		grpc.MaxCallRecvMsgSize(grpcDescriptorBytes+grpcReflectionOverhead),
		grpc.Peer(&remotePeer),
	)
	if err != nil {
		return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(err)},
			fmt.Errorf("open gRPC reflection v1alpha stream: %w", err)
	}
	request := &reflectionv1alpha.ServerReflectionRequest{}
	if symbol == "" {
		request.MessageRequest = &reflectionv1alpha.ServerReflectionRequest_ListServices{ListServices: ""}
	} else {
		request.MessageRequest = &reflectionv1alpha.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: symbol}
	}
	sendErr := stream.Send(request)
	if sendErr != nil && !errors.Is(sendErr, io.EOF) {
		return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(sendErr)},
			fmt.Errorf("send gRPC reflection v1alpha request: %w", sendErr)
	}
	if sendErr == nil {
		if err := stream.CloseSend(); err != nil {
			return nil, nil, grpcCallDetails{peer: remotePeer, status: status.Convert(err)},
				fmt.Errorf("close gRPC reflection v1alpha request stream: %w", err)
		}
	}
	response, err := stream.Recv()
	details := grpcReflectionDetails(stream.Header, stream.Trailer, remotePeer, err)
	if err != nil {
		return nil, nil, details, fmt.Errorf("receive gRPC reflection v1alpha response: %w", err)
	}
	if response.GetErrorResponse() != nil {
		err := grpcReflectionError(response.GetErrorResponse().GetErrorCode(), response.GetErrorResponse().GetErrorMessage())
		details.status = status.Convert(err)
		return nil, nil, details, err
	}
	if symbol == "" {
		services := make([]string, 0, len(response.GetListServicesResponse().GetService()))
		for _, service := range response.GetListServicesResponse().GetService() {
			services = append(services, service.GetName())
		}
		return &descriptorpb.FileDescriptorSet{}, services, details, nil
	}
	set, err := decodeGRPCDescriptors(response.GetFileDescriptorResponse().GetFileDescriptorProto())
	return set, nil, details, err
}

func grpcReflectionDetails(
	header func() (metadata.MD, error),
	trailer func() metadata.MD,
	remotePeer peer.Peer,
	err error,
) grpcCallDetails {
	responseHeader, headerErr := header()
	if headerErr != nil {
		responseHeader = nil
	}
	details := grpcCallDetails{
		header: responseHeader,
		peer:   remotePeer,
		status: status.Convert(err),
	}
	if err != nil {
		details.trailer = trailer()
	}
	return details
}

func grpcReflectionError(code int32, message string) error {
	if code < int32(codes.OK) || code > int32(codes.Unauthenticated) {
		return fmt.Errorf("gRPC reflection status: %w", status.Error(codes.Unknown, message))
	}
	return fmt.Errorf(
		"gRPC reflection status: %w",
		status.Error(codes.Code(code), message),
	)
}

func decodeGRPCDescriptors(values [][]byte) (*descriptorpb.FileDescriptorSet, error) {
	set := &descriptorpb.FileDescriptorSet{File: make([]*descriptorpb.FileDescriptorProto, 0, len(values))}
	for _, value := range values {
		file := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(value, file); err != nil {
			return nil, fmt.Errorf("parse reflected gRPC descriptor: %w", err)
		}
		set.File = append(set.File, file)
	}
	return set, nil
}
