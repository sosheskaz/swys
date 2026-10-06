package grpc_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGRPCReflectionCompletionExamples(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)

	services, directive := completeGRPCCommand(t, address, "--plaintext", "fixture.v1.E")
	assertGRPCCompletion(t, services, grpcFixtureServiceName+"/")
	assertNoGRPCCompletion(t, services, grpcFixtureMethodName)
	assertGRPCCompletionDirective(t, directive)

	methods, directive := completeGRPCCommand(t, address, "--plaintext", grpcFixtureServiceName+"/E")
	assertGRPCCompletion(t, methods, grpcFixtureMethodName)
	assertNoGRPCCompletion(t, methods, grpcFixtureServiceName+"/Watch")
	assertGRPCCompletionDirective(t, directive)
	unresolved, directive := completeGRPCCommand(t, address, "--plaintext", "--describe", "fixture.v1.EchoR")
	assert.Empty(t, unresolved, "plain type prefix must not fetch additional service descriptors")
	assertGRPCCompletionDirective(t, directive)
	v1Calls, alphaCalls := record.reflectionCounts()
	assert.Equal(t, 4, v1Calls, "service listing, method listing plus descriptor, and plain type listing")
	assert.Equal(t, 0, alphaCalls)

	calls, _, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("completion invoked %d application RPCs, want none", calls)
	}
}

func TestGRPCProtosetCompletionExamples(t *testing.T) { //nolint:tparallel // subtests finish before observing offline network effects
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	request := set.File[0].MessageType[0]
	request.NestedType = append(request.NestedType, &descriptorpb.DescriptorProto{Name: proto.String("Detail")})
	protoset := writeGRPCFixtureProtoset(t, set)
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)

	tests := []struct {
		name        string
		want        string
		unwanted    string
		kind        string
		args        []string
		wantNoSpace bool
	}{
		{
			name:        "service selector continues with slash",
			args:        []string{address, "--protoset", protoset, "fixture.v1.E"},
			want:        grpcFixtureServiceName + "/",
			unwanted:    grpcFixtureMethodName,
			wantNoSpace: true,
		},
		{
			name:     "method selector contains unary methods only",
			args:     []string{address, "--protoset", protoset, grpcFixtureServiceName + "/"},
			want:     grpcFixtureMethodName,
			unwanted: grpcFixtureServiceName + "/Watch",
			kind:     "unary",
		},
		{
			name: "list service",
			args: []string{address, "--protoset", protoset, "--list", "fixture.v1.E"},
			want: grpcFixtureServiceName,
		},
		{
			name: "describe service",
			args: []string{address, "--protoset", protoset, "--describe", "fixture.v1.E"},
			want: grpcFixtureServiceName,
		},
		{
			name: "describe method uses protobuf symbol spelling",
			args: []string{address, "--protoset", protoset, "--describe", grpcFixtureServiceName + ".E"},
			want: grpcFixtureServiceName + ".Echo",
		},
		{
			name: "describe message", args: []string{address, "--protoset", protoset, "--describe", "fixture.v1.EchoR"},
			want: "fixture.v1.EchoRequest", kind: "message",
		},
		{
			name: "describe enum", args: []string{address, "--protoset", protoset, "--describe", "fixture.v1.M"},
			want: "fixture.v1.Mode", kind: "enum",
		},
		{
			name: "describe nested user message", args: []string{address, "--protoset", protoset, "--describe", "fixture.v1.EchoRequest."},
			want: "fixture.v1.EchoRequest.Detail", unwanted: "fixture.v1.EchoRequest.LabelsEntry", kind: "message",
		},
		{
			name: "data permits later method selection",
			args: []string{address, "--protoset", protoset, "--data", "", grpcFixtureServiceName + "/E"},
			want: grpcFixtureMethodName,
		},
		{
			name: "list value replacement remains available",
			args: []string{address, "--protoset", protoset, "--list", "", "--list", "fixture.v1.E"},
			want: grpcFixtureServiceName,
		},
	}

	for _, test := range tests { //nolint:paralleltest // observe network effects after every offline completion finishes
		t.Run(test.name, func(t *testing.T) {
			values, directive := completeGRPCCommand(t, test.args...)
			assertGRPCCompletion(t, values, test.want)
			if test.kind != "" {
				for _, value := range values {
					candidate, description, _ := strings.Cut(value, "\t")
					if candidate == test.want {
						assert.Contains(t, strings.ToLower(description), test.kind, "candidate kind")
						if test.kind == "unary" {
							assert.GreaterOrEqual(t, strings.Count(description, "fixture.v1.EchoRequest"), 2, "input and output types")
						}
					}
				}
			}
			if test.unwanted != "" {
				assertNoGRPCCompletion(t, values, test.unwanted)
			}
			assertGRPCCompletionDirective(t, directive)
			if test.wantNoSpace && directive&cobra.ShellCompDirectiveNoSpace == 0 {
				t.Fatalf("completion directive = %v, want cursor continuation", directive)
			}
		})
	}

	values, directive := completeGRPCCommand(t, address, "--protoset", protoset, "unmatched")
	if len(values) != 0 {
		t.Fatalf("unmatched prefix completion = %q, want none", values)
	}
	assertGRPCCompletionDirective(t, directive)
	values, directive = completeGRPCCommand(t, address, "--protoset", protoset, "--list", "", grpcFixtureServiceName+"/E")
	assert.Empty(t, values, "changed empty list excludes a method selector")
	assertGRPCCompletionDirective(t, directive)
	stdout, _, err := executeRootStreams(
		t, "__completeNoDesc", "grpc", address, "--protoset", protoset, grpcFixtureServiceName+"/E",
	)
	require.NoError(t, err)
	assert.Contains(t, strings.Split(stdout, "\n"), grpcFixtureMethodName)
	assert.NotContains(t, stdout, "\t", "NoDesc emits candidate tokens without descriptions")
	if connections := record.connectionCount(); connections != 0 {
		t.Fatalf("offline protoset completion opened %d network connections, want none", connections)
	}
}

func completeGRPCCommand(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	values, directive, _ := completeGRPCCommandWithRoot(t, newRootCmd(), args...)
	return values, directive
}

func completeGRPCCommandWithRoot(
	t *testing.T,
	root *cobra.Command,
	args ...string,
) ([]string, cobra.ShellCompDirective, string) {
	t.Helper()
	stdout, stderr, err := executeRootCommandStreams(t, root, append([]string{"__complete", "grpc"}, args...)...)
	require.NoError(t, err, "complete %q: %v", args, err)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("completion output = %q, want directive", stdout)
	}
	directiveText := strings.TrimPrefix(lines[len(lines)-1], ":")
	if directiveText == "" || strings.IndexFunc(directiveText, func(char rune) bool {
		return char < '0' || char > '9'
	}) >= 0 {

		t.Fatalf("completion directive = %q, want decimal", directiveText)
	}
	var directive cobra.ShellCompDirective
	for _, char := range directiveText {
		directive = directive*10 + cobra.ShellCompDirective(char-'0')
	}
	return lines[:len(lines)-1], directive, stderr
}

func assertGRPCCompletion(t *testing.T, values []string, want string) {
	t.Helper()
	if !slices.ContainsFunc(values, func(value string) bool {
		candidate, _, _ := strings.Cut(value, "\t")
		return candidate == want
	}) {

		t.Fatalf("completion = %q, missing %q", values, want)
	}
}

func assertNoGRPCCompletion(t *testing.T, values []string, unwanted string) {
	t.Helper()
	if slices.ContainsFunc(values, func(value string) bool {
		candidate, _, _ := strings.Cut(value, "\t")
		return candidate == unwanted
	}) {

		t.Fatalf("completion = %q, unexpectedly contains %q", values, unwanted)
	}
}

func assertGRPCCompletionDirective(t *testing.T, directive cobra.ShellCompDirective) {
	t.Helper()
	if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Fatalf("completion directive = %v, want no filename fallback", directive)
	}
}
