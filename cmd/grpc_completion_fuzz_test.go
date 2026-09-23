package cmd

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
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
		schema := &grpcSchema{services: []string{service}}
		for _, kind := range []grpcCompletionKind{grpcCompleteSelector, grpcCompleteService, grpcCompleteSymbol} {
			for _, completion := range grpcCompletionCandidates(schema, "", kind) {
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
