package connectrpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync/atomic"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/grpcreflect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/sosheskaz/swys/internal/protoschema"
)

var errReflection = errors.New("invalid reflection schema")

// ErrReflectionProtocol identifies a server that rejects Connect-protocol
// reflection requests, as gRPC-only servers do.
var ErrReflectionProtocol = errors.New("server does not accept Connect-protocol reflection")

// Reflect lists services, or resolves only the requested symbol and its imports.
// Reflection uses the Connect protocol like application calls. Each request uses
// its own bidirectional stream, which still requires HTTP/2.
func Reflect(parent context.Context, base *url.URL, options Options, symbol string) (*protoschema.Schema, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	options.RequireHTTP2 = true
	httpClient, transport := newHTTPClient(Endpoint{URL: base}, options)
	defer transport.CloseIdleConnections()
	media := &mediaTypeRecorder{next: httpClient.Transport}
	httpClient.Transport = media
	wire := connecthttp.NewTransport(httpClient, base.Scheme+"://"+base.Host,
		connecthttp.WithReadMaxBytes(protoschema.MaxBytes+64<<10),
		connecthttp.WithSendMaxBytes(protoschema.MaxBytes),
	)
	client := grpcreflect.NewClient(connect.NewClient(wire, endRequestAfterSend))
	schema, err := reflectSchema(reflectionStreams{ctx: ctx, cancel: cancel, client: client}, symbol)
	if err != nil && media.rejected.Load() {
		err = fmt.Errorf("%w: %w", ErrReflectionProtocol, err)
	}
	return schema, err
}

// mediaTypeRecorder notes HTTP 415 responses, which Connect-Go reports only as
// error text.
type mediaTypeRecorder struct {
	next     http.RoundTripper
	rejected atomic.Bool
}

// RoundTrip records a 415 response without changing the exchange.
func (recorder *mediaTypeRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := recorder.next.RoundTrip(request)
	if err == nil && response.StatusCode == http.StatusUnsupportedMediaType {
		recorder.rejected.Store(true)
	}
	return response, err //nolint:wrapcheck // requestTransport already describes transport failures
}

// endRequestAfterSend ends each reflection stream's request body after its
// first message, as single-message calls do. Some gateways forward a request
// only after its body ends, so a stream that kept its request open while
// awaiting a response would never receive one.
func endRequestAfterSend(next connect.ClientFunc) connect.ClientFunc {
	return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
		stream, err := next(ctx, spec)
		if err != nil {
			return nil, err
		}
		return requestEndingStream{stream}, nil
	}
}

type requestEndingStream struct{ connect.ClientStream }

// Send ends the request body after delivering message.
func (stream requestEndingStream) Send(message any) error {
	if err := stream.ClientStream.Send(message); err != nil {
		return err //nolint:wrapcheck // grpcreflect inspects the stream's own errors
	}
	return stream.CloseSend() //nolint:wrapcheck // grpcreflect inspects the stream's own errors
}

// reflectionStreams opens a stream per request because endRequestAfterSend
// leaves each stream able to carry only one.
type reflectionStreams struct {
	ctx    context.Context //nolint:containedctx // one Reflect call owns every stream
	cancel context.CancelFunc
	client *grpcreflect.Client
}

func exchange[T any](streams reflectionStreams, request func(*grpcreflect.ClientStream) (T, error)) (T, error) {
	stream := streams.client.NewStream(streams.ctx)
	response, err := request(stream)
	if err != nil {
		streams.cancel()
	}
	if closeErr := stream.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("finish reflection: %w", closeErr))
	}
	return response, err
}

func reflectSchema(streams reflectionStreams, symbol string) (*protoschema.Schema, error) {
	if symbol == "" {
		names, err := exchange(streams, (*grpcreflect.ClientStream).ListServices)
		if err != nil {
			return nil, fmt.Errorf("list reflected services: %w", err)
		}
		services := make([]string, len(names))
		for i, name := range names {
			if !name.IsValid() {
				return nil, fmt.Errorf("%w: invalid service name %q", errReflection, name)
			}
			services[i] = string(name)
		}
		sort.Strings(services)
		return &protoschema.Schema{Services: services}, nil
	}
	files, err := exchange(streams, func(stream *grpcreflect.ClientStream) ([]*descriptorpb.FileDescriptorProto, error) {
		return stream.FileContainingSymbol(protoreflect.FullName(symbol))
	})
	if err != nil {
		return nil, fmt.Errorf("reflect symbol %q: %w", symbol, err)
	}
	set, err := collectDescriptors(func(name string) ([]*descriptorpb.FileDescriptorProto, error) {
		return exchange(streams, func(stream *grpcreflect.ClientStream) ([]*descriptorpb.FileDescriptorProto, error) {
			return stream.FileByFilename(name)
		})
	}, files)
	if err != nil {
		return nil, err
	}
	return protoschema.New(set)
}

func collectDescriptors(
	fetch func(string) ([]*descriptorpb.FileDescriptorProto, error), initial []*descriptorpb.FileDescriptorProto,
) (*descriptorpb.FileDescriptorSet, error) {
	set := &descriptorpb.FileDescriptorSet{}
	known := make(map[string]*descriptorpb.FileDescriptorProto)
	add := func(files []*descriptorpb.FileDescriptorProto) error {
		if len(files) > protoschema.MaxFiles {
			return fmt.Errorf("%w: reflection returned too many files", protoschema.ErrLimit)
		}
		for _, file := range files {
			name := file.GetName()
			if name == "" {
				return fmt.Errorf("%w: descriptor has no filename", errReflection)
			}
			if previous, exists := known[name]; exists {
				if !proto.Equal(previous, file) {
					return fmt.Errorf("%w: conflicting descriptor %q", errReflection, name)
				}
				continue
			}
			known[name] = file
			set.File = append(set.File, file)
		}
		return protoschema.Validate(set)
	}
	if err := add(initial); err != nil {
		return nil, err
	}
	for index := 0; index < len(set.File); index++ { //nolint:intrange // newly fetched imports extend the queue
		for _, dependency := range set.File[index].GetDependency() {
			if _, exists := known[dependency]; exists {
				continue
			}
			files, err := fetch(dependency)
			if err != nil {
				return nil, fmt.Errorf("reflect import %q: %w", dependency, err)
			}
			if err := add(files); err != nil {
				return nil, err
			}
			if _, exists := known[dependency]; !exists {
				return nil, fmt.Errorf("%w: response omitted import %q", errReflection, dependency)
			}
		}
	}
	return set, nil
}
