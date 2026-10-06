package grpc_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	grpccommand "github.com/sosheskaz/swys/cmd/internal/commands/grpc"
)

func FuzzGRPCCompletionRejectsLineInjection(f *testing.F) {
	for _, seed := range []string{
		grpcFixtureServiceName,
		"forged.v1.Service\ninjected-completion",
		"forged.v1.Service\r--output=stolen",
		"forged.v1.Service\tdescription",
		"\x1b[2Jforged.v1.Service",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, service string) {
		for _, kind := range []int{grpccommand.TestCompleteSelector, grpccommand.TestCompleteService, grpccommand.TestCompleteSymbol} {
			for _, completion := range grpccommand.ExportCompletionCandidates(service, "", kind) {
				if strings.ContainsAny(completion, "\r\n\t") {
					t.Fatalf("service %q injected completion line %q", service, completion)
				}
				candidate := strings.TrimSuffix(completion, "/")
				if !protoreflect.FullName(candidate).IsValid() {
					t.Fatalf("service %q produced invalid completion %q", service, completion)
				}
			}
		}
	})
}
