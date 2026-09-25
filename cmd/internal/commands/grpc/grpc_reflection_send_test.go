package grpc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"

	grpccommand "github.com/sosheskaz-systems/npc/cmd/internal/commands/grpc"
)

var errGRPCTestReflectionSend = errors.New("fixture reflection send failed")

func TestGRPCReflectionSendEOFUsesTerminalStatusForV1Fallback(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionV1Alpha, false)
	var receiveCalls atomic.Int32
	connection := newGRPCSendOverrideConnection(
		t,
		address,
		reflectionv1.ServerReflection_ServerReflectionInfo_FullMethodName,
		io.EOF,
		true,
		&receiveCalls,
	)

	services, err := grpccommand.ExportReflectSchema(t.Context(), connection)
	require.NoError(t, err, "recover v1 terminal status and fall back to v1alpha: %v", err)
	if !slices.Contains(services, grpcFixtureServiceName) {
		t.Fatalf("fallback services = %q, missing %q", services, grpcFixtureServiceName)
	}
	if calls := receiveCalls.Load(); calls != 1 {
		t.Fatalf("v1 receives after Send EOF = %d, want one terminal-status receive", calls)
	}
	if _, alphaCalls := record.reflectionCounts(); alphaCalls != 1 {
		t.Fatalf("v1alpha fallback calls = %d, want one", alphaCalls)
	}
}

func TestGRPCReflectionPreservesNonEOFSendError(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	var receiveCalls atomic.Int32
	connection := newGRPCSendOverrideConnection(
		t,
		address,
		reflectionv1.ServerReflection_ServerReflectionInfo_FullMethodName,
		errGRPCTestReflectionSend,
		false,
		&receiveCalls,
	)

	set, services, err := grpccommand.ExportReflectV1(t.Context(), connection)
	require.ErrorIs(t, err, errGRPCTestReflectionSend)
	if set != nil || services != nil {
		t.Fatalf("v1 non-EOF send error returned descriptors=%v services=%q", set, services)
	}
	if calls := receiveCalls.Load(); calls != 0 {
		t.Fatalf("v1 receives after non-EOF send error = %d, want none", calls)
	}
}

func TestGRPCReflectionV1AlphaSendEOFUsesTerminalStatus(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionV1, false)
	var receiveCalls atomic.Int32
	connection := newGRPCSendOverrideConnection(
		t,
		address,
		reflectionv1alpha.ServerReflection_ServerReflectionInfo_FullMethodName,
		io.EOF,
		true,
		&receiveCalls,
	)

	reflectionStatus, err := grpccommand.ExportReflectV1Alpha(t.Context(), connection)
	if code := status.Code(err); code != codes.Unimplemented {
		t.Fatalf("v1alpha terminal status = %v, want %v; error=%v", code, codes.Unimplemented, err)
	}
	if code := reflectionStatus.Code(); code != codes.Unimplemented {
		t.Fatalf("v1alpha recorded status = %v, want %v", code, codes.Unimplemented)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("v1alpha error = %v, terminal status was masked by Send EOF", err)
	}
	if calls := receiveCalls.Load(); calls != 1 {
		t.Fatalf("v1alpha receives after Send EOF = %d, want one terminal-status receive", calls)
	}
}

type grpcSendOverrideStream struct {
	grpc.ClientStream
	sendErr      error
	receiveCalls *atomic.Int32
	forwardSend  bool
}

func (stream *grpcSendOverrideStream) SendMsg(message any) error {
	if stream.forwardSend {
		err := stream.ClientStream.SendMsg(message)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("forward intercepted reflection request: %w", err)
		}
	}
	return stream.sendErr
}

func (stream *grpcSendOverrideStream) RecvMsg(message any) error {
	stream.receiveCalls.Add(1)
	return stream.ClientStream.RecvMsg(message) //nolint:wrapcheck // preserve the real terminal stream status
}

func newGRPCSendOverrideConnection(
	t *testing.T,
	address string,
	method string,
	sendErr error,
	forwardSend bool,
	receiveCalls *atomic.Int32,
) *grpc.ClientConn {
	t.Helper()

	connection, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStreamInterceptor(func(
			ctx context.Context,
			descriptor *grpc.StreamDesc,
			client *grpc.ClientConn,
			actualMethod string,
			streamer grpc.Streamer,
			options ...grpc.CallOption,
		) (grpc.ClientStream, error) {
			stream, err := streamer(ctx, descriptor, client, actualMethod, options...)
			if err != nil || actualMethod != method {
				return stream, err
			}
			return &grpcSendOverrideStream{
				ClientStream: stream,
				sendErr:      sendErr,
				receiveCalls: receiveCalls,
				forwardSend:  forwardSend,
			}, nil
		}),
	)
	require.NoError(t, err, "create intercepted gRPC client: %v", err)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close intercepted gRPC client: %v", err)
		}
	})
	return connection
}
