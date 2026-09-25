// Package grpc exposes private test witnesses to external command tests.
package grpc

import (
	"context"

	"github.com/spf13/cobra"
	grpcapi "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	TestCompleteSelector = int(grpcCompleteSelector)
	TestCompleteService  = int(grpcCompleteService)
	TestCompleteSymbol   = int(grpcCompleteSymbol)
)

func ExportCompletionCandidates(service, prefix string, kind int) []string {
	return grpcCompletionCandidates(&grpcSchema{services: []string{service}}, prefix, grpcCompletionKind(kind))
}

func ExportStatusError(operation string, err error) error { return grpcStatusError(operation, err) }

func ExportDiagnostics(protoset string, rpcStatus *status.Status) []byte {
	return grpcDiagnostics(&grpcOptions{protoset: protoset}, grpcCallDetails{status: rpcStatus})
}

func ExportDial(cmd *cobra.Command, endpoint string) (*grpcapi.ClientConn, error) {
	connection, _, err := dialGRPC(cmd, endpoint, &grpcOptions{plaintext: true})
	return connection, err
}

type TestReflectionResult struct {
	Header  metadata.MD
	Trailer metadata.MD
	Status  codes.Code
}

func ExportReflectionDetails(header func() (metadata.MD, error), trailer func() metadata.MD, remotePeer peer.Peer, err error) TestReflectionResult {
	details := grpcReflectionDetails(header, trailer, remotePeer, err)
	return TestReflectionResult{Header: details.header, Trailer: details.trailer, Status: details.status.Code()}
}

func ExportReadRequestFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	return readGRPCRequestFile(ctx, path, limit)
}

func ExportReflectSchema(ctx context.Context, connection *grpcapi.ClientConn) ([]string, error) {
	schema, _, err := reflectGRPCSchema(ctx, connection, "", "", "")
	if err != nil {
		return nil, err
	}
	return schema.services, nil
}

func ExportReflectV1(ctx context.Context, connection *grpcapi.ClientConn) (*descriptorpb.FileDescriptorSet, []string, error) {
	set, services, _, err := reflectGRPCV1(ctx, connection, "")
	return set, services, err
}

func ExportReflectV1Alpha(ctx context.Context, connection *grpcapi.ClientConn) (*status.Status, error) {
	_, _, details, err := reflectGRPCV1Alpha(ctx, connection, "")
	return details.status, err
}
