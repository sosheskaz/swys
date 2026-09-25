package grpc_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
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

	calls, _, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("completion invoked %d application RPCs, want none", calls)
	}
}

func TestGRPCProtosetCompletionExamples(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)

	tests := []struct {
		name        string
		want        string
		unwanted    string
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values, directive := completeGRPCCommand(t, test.args...)
			assertGRPCCompletion(t, values, test.want)
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
