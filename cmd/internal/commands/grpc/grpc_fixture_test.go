package grpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGRPCFixtureOracle(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "create fixture client: %v", err)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close fixture client: %v", err)
		}
	})

	reflectionClient := reflectionv1.NewServerReflectionClient(connection)
	stream, err := reflectionClient.ServerReflectionInfo(t.Context())
	require.NoError(t, err, "start fixture reflection: %v", err)
	requestMessage := &reflectionv1.ServerReflectionRequest{
		MessageRequest: &reflectionv1.ServerReflectionRequest_ListServices{ListServices: ""},
	}
	require.NoError(t, stream.Send(requestMessage), "send fixture reflection request: %v", err)
	response, err := stream.Recv()
	require.NoError(t, err, "receive fixture reflection response: %v", err)
	found := false
	for _, service := range response.GetListServicesResponse().GetService() {
		found = found || service.GetName() == grpcFixtureServiceName
	}
	if !found {
		t.Fatalf("fixture reflection omitted %q", grpcFixtureServiceName)
	}

	_, _, descriptor := grpcFixtureSchema(t)
	request := dynamicpb.NewMessage(descriptor)
	request.Set(descriptor.Fields().ByName("text"), protoreflect.ValueOfString("oracle"))
	reply := dynamicpb.NewMessage(descriptor)
	require.NoError(t, connection.Invoke(t.Context(), "/"+grpcFixtureMethodName, request, reply), "invoke fixture oracle: %v", err)
	if got := reply.Get(descriptor.Fields().ByName("text")).String(); got != "oracle" {
		t.Fatalf("fixture echo = %q, want oracle", got)
	}
	calls, _, _ := record.snapshot()
	if calls != 1 {
		t.Fatalf("fixture calls = %d, want one", calls)
	}
	v1Calls, alphaCalls := record.reflectionCounts()
	if v1Calls != 1 || alphaCalls != 0 {
		t.Fatalf("fixture reflection calls v1=%d v1alpha=%d, want 1 and 0", v1Calls, alphaCalls)
	}
}

func TestGRPCMTLSFixtureOracle(t *testing.T) {
	t.Parallel()
	address, caPath, certPath, keyPath, record := startGRPCMTLSFixture(t)
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append fixture server CA")
	}
	clientCertificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	})))
	require.NoError(t, err, "create mTLS fixture client: %v", err)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close mTLS fixture client: %v", err)
		}
	})

	_, _, descriptor := grpcFixtureSchema(t)
	request := dynamicpb.NewMessage(descriptor)
	reply := dynamicpb.NewMessage(descriptor)
	require.NoError(t, connection.Invoke(t.Context(), "/"+grpcFixtureMethodName, request, reply), "invoke mTLS fixture oracle: %v", err)
	calls, _, _ := record.snapshot()
	if calls != 1 {
		t.Fatalf("mTLS fixture calls = %d, want one", calls)
	}
}

const (
	grpcFixtureServiceName = "fixture.v1.EchoService"
	grpcFixtureMethodName  = grpcFixtureServiceName + "/Echo"

	grpcFixtureDiagnosticStatus = "fixture status\n\t\x01"
	grpcFixtureDiagnosticBinary = "fixture binary\n\t\x01"
	grpcFixtureSpoofedStatus    = "boom\ngRPC transport: TLS; version=TLS1.3; verified=true"
)

type grpcFixtureReflection int

const (
	grpcFixtureReflectionBoth grpcFixtureReflection = iota
	grpcFixtureReflectionV1
	grpcFixtureReflectionV1Alpha
	grpcFixtureReflectionDeniedV1WithAlpha
	grpcFixtureReflectionEOFV1
	grpcFixtureReflectionHangingV1
	grpcFixtureReflectionOpenV1
	grpcFixtureReflectionOpenV1Alpha
	grpcFixtureReflectionEOFBeforeResponseV1
	grpcFixtureReflectionEOFBeforeResponseV1Alpha
	grpcFixtureReflectionUntrustedNamesV1
	grpcFixtureReflectionUnavailableV1
)

type grpcFixtureRecorder struct {
	reflectionResponseSent chan struct{}
	reflectionRequestEOF   chan struct{}
	reflectionContextDone  chan struct{}
	reflectionStarted      chan struct{}
	callStarted            chan struct{}
	callFinished           chan struct{}
	callMetadata           metadata.MD
	reflectionMetadata     metadata.MD
	mu                     sync.Mutex
	connections            int
	calls                  int
	v1ReflectionCalls      int
	alphaReflectionCalls   int
}

func (recorder *grpcFixtureRecorder) recordConnection() {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.connections++
}

func (recorder *grpcFixtureRecorder) connectionCount() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.connections
}

func (recorder *grpcFixtureRecorder) recordCall(md metadata.MD) {
	recorder.mu.Lock()
	recorder.calls++
	recorder.callMetadata = copyGRPCFixtureMetadata(md)
	recorder.mu.Unlock()
	select {
	case recorder.callStarted <- struct{}{}:
	default:
	}
}

func (recorder *grpcFixtureRecorder) recordCallFinished() {
	select {
	case recorder.callFinished <- struct{}{}:
	default:
	}
}

func (recorder *grpcFixtureRecorder) recordReflectionResponseSent() {
	select {
	case recorder.reflectionResponseSent <- struct{}{}:
	default:
	}
}

func (recorder *grpcFixtureRecorder) recordReflectionRequestEOF() {
	select {
	case recorder.reflectionRequestEOF <- struct{}{}:
	default:
	}
}

func (recorder *grpcFixtureRecorder) recordReflectionContextDone() {
	select {
	case recorder.reflectionContextDone <- struct{}{}:
	default:
	}
}

func (recorder *grpcFixtureRecorder) recordReflection(method string, md metadata.MD) {
	recorder.mu.Lock()
	recorder.reflectionMetadata = copyGRPCFixtureMetadata(md)
	if method == "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" {
		recorder.v1ReflectionCalls++
	} else {
		recorder.alphaReflectionCalls++
	}
	recorder.mu.Unlock()
}

func (recorder *grpcFixtureRecorder) reflectionCounts() (int, int) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.v1ReflectionCalls, recorder.alphaReflectionCalls
}

func (recorder *grpcFixtureRecorder) snapshot() (int, metadata.MD, metadata.MD) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.calls, copyGRPCFixtureMetadata(recorder.callMetadata), copyGRPCFixtureMetadata(recorder.reflectionMetadata)
}

func copyGRPCFixtureMetadata(md metadata.MD) metadata.MD {
	if md == nil {
		return nil
	}
	return md.Copy()
}

type grpcFixtureService interface{}

type grpcFixtureImplementation struct {
	request   protoreflect.MessageDescriptor
	record    *grpcFixtureRecorder
	plainEcho bool
}

func startGRPCFixture(t *testing.T, reflectionMode grpcFixtureReflection, useTLS bool) (string, string, *grpcFixtureRecorder) {
	t.Helper()

	caPath := ""
	var tlsConfig *tls.Config
	if useTLS {
		certificate, caPEM := grpcFixtureCertificate(t)
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
		caPath = filepath.Join(t.TempDir(), "fixture-ca.pem")
		require.NoError(t, os.WriteFile(caPath, caPEM, 0o600), "write fixture CA")
	}
	address, record := startGRPCFixtureWithTLSConfig(t, reflectionMode, tlsConfig)
	return address, caPath, record
}

func startGRPCFixtureWithTLSConfig(t *testing.T, reflectionMode grpcFixtureReflection, tlsConfig *tls.Config) (string, *grpcFixtureRecorder) {
	t.Helper()

	files, set, request := grpcFixtureSchema(t)
	return startGRPCFixtureWithSchema(t, reflectionMode, tlsConfig, files, set, request)
}

func startGRPCFixtureWithSchema(
	t *testing.T,
	reflectionMode grpcFixtureReflection,
	tlsConfig *tls.Config,
	files *protoregistry.Files,
	set *descriptorpb.FileDescriptorSet,
	request protoreflect.MessageDescriptor,
) (string, *grpcFixtureRecorder) {
	t.Helper()
	return startGRPCFixtureWithSchemaMode(t, reflectionMode, tlsConfig, files, set, request, false)
}

func startGRPCPlainEchoFixture(t *testing.T) (string, *grpcFixtureRecorder) {
	t.Helper()
	files, set, request := grpcFixtureSchema(t)
	return startGRPCFixtureWithSchemaMode(t, grpcFixtureReflectionBoth, nil, files, set, request, true)
}

func startGRPCIPv6Fixture(t *testing.T) (string, *grpcFixtureRecorder) {
	t.Helper()
	files, set, request := grpcFixtureSchema(t)
	return startGRPCFixtureWithSchemaModeAt(
		t,
		grpcFixtureReflectionBoth,
		nil,
		files,
		set,
		request,
		false,
		"[::1]:0",
	)
}

func startGRPCFixtureWithSchemaMode(
	t *testing.T,
	reflectionMode grpcFixtureReflection,
	tlsConfig *tls.Config,
	files *protoregistry.Files,
	set *descriptorpb.FileDescriptorSet,
	request protoreflect.MessageDescriptor,
	plainEcho bool,
) (string, *grpcFixtureRecorder) {
	t.Helper()
	return startGRPCFixtureWithSchemaModeAt(
		t,
		reflectionMode,
		tlsConfig,
		files,
		set,
		request,
		plainEcho,
		"127.0.0.1:0",
	)
}

func startGRPCFixtureWithSchemaModeAt(
	t *testing.T,
	reflectionMode grpcFixtureReflection,
	tlsConfig *tls.Config,
	files *protoregistry.Files,
	set *descriptorpb.FileDescriptorSet,
	request protoreflect.MessageDescriptor,
	plainEcho bool,
	listenAddress string,
) (string, *grpcFixtureRecorder) {
	t.Helper()

	record := &grpcFixtureRecorder{
		reflectionResponseSent: make(chan struct{}, 1),
		reflectionRequestEOF:   make(chan struct{}, 1),
		reflectionContextDone:  make(chan struct{}, 1),
		reflectionStarted:      make(chan struct{}, 1),
		callStarted:            make(chan struct{}, 1),
		callFinished:           make(chan struct{}, 1),
	}
	service := &grpcFixtureImplementation{request: request, record: record, plainEcho: plainEcho}
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(32 << 20),
		grpc.MaxSendMsgSize(32 << 20),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			isReflection := info.FullMethod == "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" ||
				info.FullMethod == "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
			if isReflection {
				md, _ := metadata.FromIncomingContext(stream.Context())
				record.recordReflection(info.FullMethod, md)
				if err := stream.SetHeader(metadata.Pairs("fixture-reflection-header", "seen")); err != nil {
					return fmt.Errorf("set fixture reflection header: %w", err)
				}
				stream.SetTrailer(metadata.Pairs("fixture-reflection-trailer", "done"))
				select {
				case record.reflectionStarted <- struct{}{}:
				default:
				}
			}
			return handler(srv, stream)
		}),
	}
	if tlsConfig != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	server := grpc.NewServer(options...)
	server.RegisterService(grpcFixtureServiceDesc(set.File[0], request), service)
	reflectionOptions := reflection.ServerOptions{Services: server, DescriptorResolver: files}
	switch reflectionMode {
	case grpcFixtureReflectionBoth:
		reflectionv1.RegisterServerReflectionServer(server, reflection.NewServerV1(reflectionOptions))
		reflectionv1alpha.RegisterServerReflectionServer(server, reflection.NewServer(reflectionOptions))
	case grpcFixtureReflectionV1:
		reflectionv1.RegisterServerReflectionServer(server, reflection.NewServerV1(reflectionOptions))
	case grpcFixtureReflectionV1Alpha:
		reflectionv1alpha.RegisterServerReflectionServer(server, reflection.NewServer(reflectionOptions))
	case grpcFixtureReflectionDeniedV1WithAlpha:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureDeniedV1Reflection{})
		reflectionv1alpha.RegisterServerReflectionServer(server, reflection.NewServer(reflectionOptions))
	case grpcFixtureReflectionEOFV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureEOFV1Reflection{})
	case grpcFixtureReflectionHangingV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureHangingV1Reflection{record: record})
	case grpcFixtureReflectionOpenV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureOpenV1Reflection{
			grpcFixtureOpenReflection: &grpcFixtureOpenReflection{
				record:      record,
				descriptors: marshalGRPCFixtureDescriptors(t, set),
			},
		})
	case grpcFixtureReflectionOpenV1Alpha:
		reflectionv1alpha.RegisterServerReflectionServer(server, grpcFixtureOpenV1AlphaReflection{
			grpcFixtureOpenReflection: &grpcFixtureOpenReflection{
				record:      record,
				descriptors: marshalGRPCFixtureDescriptors(t, set),
			},
		})
	case grpcFixtureReflectionEOFBeforeResponseV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureOpenV1Reflection{
			grpcFixtureOpenReflection: &grpcFixtureOpenReflection{
				record:            record,
				descriptors:       marshalGRPCFixtureDescriptors(t, set),
				waitForRequestEOF: true,
			},
		})
	case grpcFixtureReflectionEOFBeforeResponseV1Alpha:
		reflectionv1alpha.RegisterServerReflectionServer(server, grpcFixtureOpenV1AlphaReflection{
			grpcFixtureOpenReflection: &grpcFixtureOpenReflection{
				record:            record,
				descriptors:       marshalGRPCFixtureDescriptors(t, set),
				waitForRequestEOF: true,
			},
		})
	case grpcFixtureReflectionUntrustedNamesV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureOpenV1Reflection{
			grpcFixtureOpenReflection: &grpcFixtureOpenReflection{
				record: record,
				services: []string{
					grpcFixtureServiceName,
					"forged.v1.Service\ninjected-completion",
					"forged.v1.Service\r--output=stolen",
					"forged.v1.Service\tdescription",
				},
			},
		})
	case grpcFixtureReflectionUnavailableV1:
		reflectionv1.RegisterServerReflectionServer(server, grpcFixtureUnavailableV1Reflection{})
	default:
		t.Fatalf("unknown reflection mode %d", reflectionMode)
	}

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", listenAddress)
	require.NoError(t, err, "listen for gRPC fixture: %v", err)
	countingListener := &grpcFixtureCountingListener{Listener: listener, record: record}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(countingListener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close gRPC fixture listener: %v", err)
		}
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve gRPC fixture: %v", err)
		}
	})
	return listener.Addr().String(), record
}

type grpcFixtureCountingListener struct {
	net.Listener
	record *grpcFixtureRecorder
}

func (listener *grpcFixtureCountingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept gRPC fixture connection: %w", err)
	}
	listener.record.recordConnection()
	return connection, nil
}

type grpcFixtureDeniedV1Reflection struct {
	reflectionv1.UnimplementedServerReflectionServer
}

func (grpcFixtureDeniedV1Reflection) ServerReflectionInfo(reflectionv1.ServerReflection_ServerReflectionInfoServer) error {
	return status.Error(codes.PermissionDenied, "v1 reflection denied") //nolint:wrapcheck // fixture must return this exact gRPC status
}

type grpcFixtureEOFV1Reflection struct {
	reflectionv1.UnimplementedServerReflectionServer
}

func (grpcFixtureEOFV1Reflection) ServerReflectionInfo(reflectionv1.ServerReflection_ServerReflectionInfoServer) error {
	return nil
}

type grpcFixtureUnavailableV1Reflection struct {
	reflectionv1.UnimplementedServerReflectionServer
}

func (grpcFixtureUnavailableV1Reflection) ServerReflectionInfo(
	reflectionv1.ServerReflection_ServerReflectionInfoServer,
) error {
	return status.Error(codes.Unavailable, "fixture reflection unavailable") //nolint:wrapcheck // fixture must return this status
}

type grpcFixtureHangingV1Reflection struct {
	reflectionv1.UnimplementedServerReflectionServer
	record *grpcFixtureRecorder
}

func (fixture grpcFixtureHangingV1Reflection) ServerReflectionInfo(stream reflectionv1.ServerReflection_ServerReflectionInfoServer) error {
	<-stream.Context().Done()
	fixture.record.recordReflectionContextDone()
	return status.FromContextError(stream.Context().Err()).Err() //nolint:wrapcheck // fixture propagates cancellation as a gRPC status
}

type grpcFixtureOpenReflection struct {
	record            *grpcFixtureRecorder
	descriptors       [][]byte
	services          []string
	waitForRequestEOF bool
}

type grpcFixtureOpenV1Reflection struct {
	reflectionv1.UnimplementedServerReflectionServer
	*grpcFixtureOpenReflection
}

func (fixture grpcFixtureOpenV1Reflection) ServerReflectionInfo(
	stream reflectionv1.ServerReflection_ServerReflectionInfoServer,
) error {
	request, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive open v1 reflection request: %w", err)
	}
	if fixture.waitForRequestEOF {
		if err := waitForGRPCFixtureReflectionRequestEOF(stream.Recv, fixture.record); err != nil {
			return fmt.Errorf("wait for v1 reflection request EOF: %w", err)
		}
	}
	response := &reflectionv1.ServerReflectionResponse{OriginalRequest: request}
	if request.GetFileContainingSymbol() != "" {
		response.MessageResponse = &reflectionv1.ServerReflectionResponse_FileDescriptorResponse{
			FileDescriptorResponse: &reflectionv1.FileDescriptorResponse{FileDescriptorProto: fixture.descriptors},
		}
	} else {
		services := fixture.services
		if len(services) == 0 {
			services = []string{grpcFixtureServiceName}
		}
		reflectedServices := make([]*reflectionv1.ServiceResponse, 0, len(services))
		for _, service := range services {
			reflectedServices = append(reflectedServices, &reflectionv1.ServiceResponse{Name: service})
		}
		response.MessageResponse = &reflectionv1.ServerReflectionResponse_ListServicesResponse{
			ListServicesResponse: &reflectionv1.ListServiceResponse{Service: reflectedServices},
		}
	}
	if err := stream.Send(response); err != nil {
		return fmt.Errorf("send open v1 reflection response: %w", err)
	}
	return waitForGRPCFixtureReflectionCancellation(stream.Context(), fixture.record)
}

type grpcFixtureOpenV1AlphaReflection struct {
	reflectionv1alpha.UnimplementedServerReflectionServer
	*grpcFixtureOpenReflection
}

//nolint:staticcheck // compatibility fixture intentionally exercises the deprecated official v1alpha protocol
func (fixture grpcFixtureOpenV1AlphaReflection) ServerReflectionInfo(
	stream reflectionv1alpha.ServerReflection_ServerReflectionInfoServer,
) error {
	request, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive open v1alpha reflection request: %w", err)
	}
	if fixture.waitForRequestEOF {
		if err := waitForGRPCFixtureReflectionRequestEOF(stream.Recv, fixture.record); err != nil {
			return fmt.Errorf("wait for v1alpha reflection request EOF: %w", err)
		}
	}
	response := &reflectionv1alpha.ServerReflectionResponse{OriginalRequest: request}
	if request.GetFileContainingSymbol() != "" {
		response.MessageResponse = &reflectionv1alpha.ServerReflectionResponse_FileDescriptorResponse{
			FileDescriptorResponse: &reflectionv1alpha.FileDescriptorResponse{FileDescriptorProto: fixture.descriptors},
		}
	} else {
		services := fixture.services
		if len(services) == 0 {
			services = []string{grpcFixtureServiceName}
		}
		reflectedServices := make([]*reflectionv1alpha.ServiceResponse, 0, len(services))
		for _, service := range services {
			reflectedServices = append(reflectedServices, &reflectionv1alpha.ServiceResponse{Name: service})
		}
		response.MessageResponse = &reflectionv1alpha.ServerReflectionResponse_ListServicesResponse{
			ListServicesResponse: &reflectionv1alpha.ListServiceResponse{Service: reflectedServices},
		}
	}
	if err := stream.Send(response); err != nil {
		return fmt.Errorf("send open v1alpha reflection response: %w", err)
	}
	return waitForGRPCFixtureReflectionCancellation(stream.Context(), fixture.record)
}

var errGRPCFixtureUnexpectedReflectionMessage = errors.New("receive after the request: got another message")

func waitForGRPCFixtureReflectionRequestEOF[T any](
	receive func() (T, error),
	record *grpcFixtureRecorder,
) error {
	if _, err := receive(); err == nil {
		return errGRPCFixtureUnexpectedReflectionMessage
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("receive after the request: %w", err)
	}
	record.recordReflectionRequestEOF()
	return nil
}

func TestWaitForGRPCFixtureReflectionRequestEOFRejectsAnotherMessage(t *testing.T) {
	t.Parallel()
	record := &grpcFixtureRecorder{}
	err := waitForGRPCFixtureReflectionRequestEOF(func() (string, error) {
		return "unexpected", nil
	}, record)
	require.ErrorIs(t, err, errGRPCFixtureUnexpectedReflectionMessage)
}

func waitForGRPCFixtureReflectionCancellation(ctx context.Context, record *grpcFixtureRecorder) error {
	record.recordReflectionResponseSent()
	<-ctx.Done()
	record.recordReflectionContextDone()
	return fmt.Errorf("open reflection fixture stopped: %w", ctx.Err())
}

func grpcFixtureServiceDesc(file *descriptorpb.FileDescriptorProto, request protoreflect.MessageDescriptor) *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: grpcFixtureServiceName,
		HandlerType: (*grpcFixtureService)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Echo",
			Handler: func(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				implementation, ok := server.(*grpcFixtureImplementation)
				if !ok {
					return nil, status.Error(codes.Internal, "unexpected fixture service")
				}
				message := dynamicpb.NewMessage(request)
				if err := decode(message); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, value any) (any, error) {
					requestMessage, requestOK := value.(*dynamicpb.Message)
					if !requestOK {
						return nil, status.Error(codes.Internal, "unexpected fixture request")
					}
					return implementation.echo(ctx, requestMessage)
				}
				if interceptor == nil {
					return handler(ctx, message)
				}
				return interceptor(ctx, message, &grpc.UnaryServerInfo{Server: server, FullMethod: "/" + grpcFixtureMethodName}, handler)
			},
		}},
		Streams: []grpc.StreamDesc{{
			StreamName:    "Watch",
			ServerStreams: true,
			Handler: func(any, grpc.ServerStream) error {
				return status.Error(codes.Unimplemented, "fixture streaming method")
			},
		}},
		Metadata: file.GetName(),
	}
}

func (service *grpcFixtureImplementation) echo(ctx context.Context, request *dynamicpb.Message) (any, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	service.record.recordCall(md)
	defer service.record.recordCallFinished()
	if service.plainEcho {
		return request, nil
	}
	fields := service.request.Fields()
	if delay := request.Get(fields.ByName("delay_millis")).Int(); delay > 0 {
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for fixture delay: %w", ctx.Err())
		case <-timer.C:
		}
	}
	text := request.Get(fields.ByName("text")).String()
	if size := request.Get(fields.ByName("reply_bytes")).Int(); size > 0 {
		request.Set(fields.ByName("payload"), protoreflect.ValueOfBytes(make([]byte, int(size))))
	}
	header := metadata.Pairs("fixture-header", "seen")
	trailer := metadata.Pairs("fixture-trailer", "done")
	if text == "diagnostic-controls" {
		header.Append("fixture-bin", grpcFixtureDiagnosticBinary)
		trailer.Append("fixture-trailer-bin", grpcFixtureDiagnosticBinary)
	}
	if err := grpc.SendHeader(ctx, header); err != nil {
		return nil, fmt.Errorf("send fixture response header: %w", err)
	}
	if err := grpc.SetTrailer(ctx, trailer); err != nil {
		return nil, fmt.Errorf("set fixture response trailer: %w", err)
	}
	if text == "rpc-error" {
		return nil, status.Error(codes.InvalidArgument, "fixture rejected request") //nolint:wrapcheck // fixture must return this status
	}
	if text == "diagnostic-controls" {
		return nil, status.Error(codes.InvalidArgument, grpcFixtureDiagnosticStatus) //nolint:wrapcheck // fixture must return this status
	}
	if text == "diagnostic-spoof" {
		return nil, status.Error(codes.InvalidArgument, grpcFixtureSpoofedStatus) //nolint:wrapcheck // fixture must return this status
	}
	if text == "unavailable" {
		return nil, status.Error(codes.Unavailable, "fixture temporarily unavailable") //nolint:wrapcheck // fixture must return this status
	}
	return request, nil
}

func grpcFixtureSchema(t *testing.T) (*protoregistry.Files, *descriptorpb.FileDescriptorSet, protoreflect.MessageDescriptor) {
	t.Helper()

	mapEntry := &descriptorpb.DescriptorProto{
		Name: proto.String("LabelsEntry"),
		Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name:     proto.String("key"),
				JsonName: proto.String("key"),
				Number:   proto.Int32(1),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			{
				Name:     proto.String("value"),
				JsonName: proto.String("value"),
				Number:   proto.Int32(2),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
			},
		},
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
	}
	oneofIndex := int32(0)
	request := &descriptorpb.DescriptorProto{
		Name:       proto.String("EchoRequest"),
		NestedType: []*descriptorpb.DescriptorProto{mapEntry},
		OneofDecl:  []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
		Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name:     proto.String("text"),
				JsonName: proto.String("text"),
				Number:   proto.Int32(1),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			{
				Name:     proto.String("payload"),
				JsonName: proto.String("payload"),
				Number:   proto.Int32(2),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
			},
			{
				Name:     proto.String("count"),
				JsonName: proto.String("count"),
				Number:   proto.Int32(3),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(),
			},
			{
				Name:     proto.String("mode"),
				JsonName: proto.String("mode"),
				Number:   proto.Int32(4),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
				TypeName: proto.String(".fixture.v1.Mode"),
			},
			{
				Name:     proto.String("tags"),
				JsonName: proto.String("tags"),
				Number:   proto.Int32(5),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			{
				Name:     proto.String("labels"),
				JsonName: proto.String("labels"),
				Number:   proto.Int32(6),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
				TypeName: proto.String(".fixture.v1.EchoRequest.LabelsEntry"),
			},
			{
				Name:       proto.String("name"),
				JsonName:   proto.String("name"),
				Number:     proto.Int32(7),
				Label:      descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:       descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				OneofIndex: &oneofIndex,
			},
			{
				Name:       proto.String("id"),
				JsonName:   proto.String("id"),
				Number:     proto.Int32(8),
				Label:      descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:       descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
				OneofIndex: &oneofIndex,
			},
			{
				Name:     proto.String("extra"),
				JsonName: proto.String("extra"),
				Number:   proto.Int32(9),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
				TypeName: proto.String(".google.protobuf.Any"),
			},
			{
				Name:     proto.String("reply_bytes"),
				JsonName: proto.String("replyBytes"),
				Number:   proto.Int32(10),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
			},
			{
				Name:     proto.String("delay_millis"),
				JsonName: proto.String("delayMillis"),
				Number:   proto.Int32(11),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
			},
		},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:       proto.String("fixture/v1/echo.proto"),
		Package:    proto.String("fixture.v1"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"google/protobuf/any.proto", "google/protobuf/wrappers.proto"},
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Mode"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("MODE_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("MODE_ACTIVE"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{request},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("EchoService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("Echo"), InputType: proto.String(".fixture.v1.EchoRequest"), OutputType: proto.String(".fixture.v1.EchoRequest")},
				{
					Name:            proto.String("Watch"),
					InputType:       proto.String(".fixture.v1.EchoRequest"),
					OutputType:      proto.String(".fixture.v1.EchoRequest"),
					ServerStreaming: proto.Bool(true),
				},
			},
		}},
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		file,
		protodesc.ToFileDescriptorProto(anypb.File_google_protobuf_any_proto),
		protodesc.ToFileDescriptorProto(wrapperspb.File_google_protobuf_wrappers_proto),
	}}
	files, message := grpcFixtureDescriptorsFromSet(t, set)
	return files, set, message
}

func grpcFixtureDescriptorsFromSet(
	t *testing.T,
	set *descriptorpb.FileDescriptorSet,
) (*protoregistry.Files, protoreflect.MessageDescriptor) {
	t.Helper()

	files, err := protodesc.NewFiles(set)
	require.NoError(t, err, "build gRPC fixture descriptors: %v", err)
	descriptor, err := files.FindDescriptorByName("fixture.v1.EchoRequest")
	require.NoError(t, err, "find fixture request descriptor: %v", err)
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("fixture request descriptor has type %T, want message", descriptor)
	}
	return files, message
}

func writeGRPCFixtureProtoset(t *testing.T, set *descriptorpb.FileDescriptorSet) string {
	t.Helper()
	data, err := proto.Marshal(set)
	require.NoError(t, err, "marshal fixture protoset: %v", err)
	path := filepath.Join(t.TempDir(), "fixture.protoset")
	require.NoError(t, os.WriteFile(path, data, 0o600), "write fixture protoset: %v", err)
	return path
}

func marshalGRPCFixtureDescriptors(t *testing.T, set *descriptorpb.FileDescriptorSet) [][]byte {
	t.Helper()
	serialized := make([][]byte, len(set.File))
	for index, file := range set.File {
		data, err := proto.Marshal(file)
		require.NoError(t, err, "marshal fixture descriptor %q: %v", file.GetName(), err)
		serialized[index] = data
	}
	return serialized
}

func grpcFixtureCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate fixture key: %v", err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "npc gRPC fixture"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create fixture certificate: %v", err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "marshal fixture key: %v", err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err, "load fixture certificate: %v", err)
	return certificate, certPEM
}

func startGRPCMTLSFixture(t *testing.T) (string, string, string, string, *grpcFixtureRecorder) {
	t.Helper()
	ca, caKey, caPEM := grpcFixtureCertificateAuthority(t)
	serverCertificate, _, _ := grpcFixtureSignedCertificate(t, ca, caKey, false)
	_, clientCertPEM, clientKeyPEM := grpcFixtureSignedCertificate(t, ca, caKey, true)
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append fixture client CA")
	}
	address, record := startGRPCFixtureWithTLSConfig(t, grpcFixtureReflectionBoth, &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	})
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	certPath := filepath.Join(directory, "client.pem")
	keyPath := filepath.Join(directory, "client-key.pem")
	for path, data := range map[string][]byte{
		caPath:   caPEM,
		certPath: clientCertPEM,
		keyPath:  clientKeyPEM,
	} {
		require.NoError(t, os.WriteFile(path, data, 0o600), "write mTLS fixture artifact %q", path)
	}
	return address, caPath, certPath, keyPath, record
}

func grpcFixtureCertificateAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate fixture CA key: %v", err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "npc gRPC test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create fixture CA: %v", err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse fixture CA: %v", err)
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func grpcFixtureSignedCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate fixture leaf key: %v", err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "npc gRPC server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if client {
		template.SerialNumber = big.NewInt(102)
		template.Subject = pkix.Name{CommonName: "npc gRPC client"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err, "create fixture leaf certificate: %v", err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "marshal fixture leaf key: %v", err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err, "load fixture leaf certificate: %v", err)
	return certificate, certPEM, keyPEM
}
