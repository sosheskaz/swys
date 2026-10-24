package grpc_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGRPCCompletionUsesSeparateTwoSecondDeadline(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	started := time.Now()
	values, directive := completeGRPCCommand(t, address, "--plaintext", "--timeout", "50ms", "")
	elapsed := time.Since(started)

	require.Empty(t, values)
	assertGRPCCompletionDirective(t, directive)
	if elapsed < 1500*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("completion elapsed = %v, want separate two-second deadline", elapsed)
	}
	if v1Calls, _ := record.reflectionCounts(); v1Calls != 1 {
		t.Fatalf("timed-out completion made %d reflection calls, want one", v1Calls)
	}
}

func TestGRPCCompletionHonorsEarlierParentCancellation(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	ctx, cancel := context.WithCancel(t.Context())
	root := newRootCmd()
	root.SetContext(ctx)
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-record.reflectionStarted:
			cancel()
		case <-ctx.Done():
		}
		close(cancelDone)
	}()

	started := time.Now()
	values, directive, stderr := completeGRPCCommandWithRoot(t, root, address, "--plaintext", "--timeout", "30s", "")
	elapsed := time.Since(started)
	<-cancelDone

	require.Empty(t, values)
	assertGRPCCompletionDirective(t, directive)
	if elapsed > time.Second {
		t.Fatalf("parent-canceled completion elapsed = %v, want under one second", elapsed)
	}
	assertQuietGRPCCompletionFailure(t, stderr)
}

func TestGRPCCompletionFailuresAreQuiet(t *testing.T) {
	t.Parallel()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	refusedAddress := listener.Addr().String()
	require.NoError(t, listener.Close())
	unsupportedAddress, _, _ := startGRPCFixture(t, grpcFixtureReflectionEOFV1, false)
	unavailableAddress, _, _ := startGRPCFixture(t, grpcFixtureReflectionUnavailableV1, false)

	tests := []struct {
		name    string
		address string
	}{
		{name: "connection refused", address: refusedAddress},
		{name: "reflection unavailable", address: unavailableAddress},
		{name: "unsupported reflection response", address: unsupportedAddress},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values, directive, stderr := completeGRPCCommandWithRoot(
				t,
				newRootCmd(),
				test.address,
				"--plaintext",
				"fixture.",
			)
			require.Empty(t, values)
			assertGRPCCompletionDirective(t, directive)
			assertQuietGRPCCompletionFailure(t, stderr)
		})
	}
}

func TestGRPCCompletionReusesTLSAndAuthentication(t *testing.T) {
	t.Parallel()

	const authorization = "Bearer completion-fixture"
	commandAddress, commandCAPath, commandRecord := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	if _, _, err := executeRootStreams(
		t,
		"grpc",
		commandAddress,
		"--ca",
		commandCAPath,
		"--header",
		"authorization: "+authorization,
		"--header",
		"x-completion-test: one",
		"--header",
		"x-completion-test: two",
	); err != nil {
		t.Fatalf("run authenticated discovery command: %v", err)
	}
	_, _, commandMetadata := commandRecord.snapshot()
	require.Equal(t, []string{authorization}, commandMetadata.Get("authorization"))
	require.Equal(t, []string{"one", "two"}, commandMetadata.Get("x-completion-test"))

	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	flags := []string{
		"--ca", caPath,
		"--header", "authorization: " + authorization,
		"--header", "x-completion-test: one",
		"--header", "x-completion-test: two",
	}

	serviceArgs := append([]string{address}, flags...)
	services, _ := completeGRPCCommand(t, append(serviceArgs, "fixture.v1.E")...)
	assertGRPCCompletion(t, services, grpcFixtureServiceName+"/")
	_, _, listMetadata := record.snapshot()
	require.Equal(t, []string{authorization}, listMetadata.Get("authorization"))
	require.Equal(t, []string{"one", "two"}, listMetadata.Get("x-completion-test"))

	methodArgs := append([]string{address}, flags...)
	methods, _ := completeGRPCCommand(t, append(methodArgs, grpcFixtureServiceName+"/E")...)
	assertGRPCCompletion(t, methods, grpcFixtureMethodName)
	calls, _, descriptorMetadata := record.snapshot()
	require.Equal(t, []string{authorization}, descriptorMetadata.Get("authorization"))
	require.Equal(t, []string{"one", "two"}, descriptorMetadata.Get("x-completion-test"))
	require.Equal(t, 0, calls, "application RPC calls")
	if v1Calls, alphaCalls := record.reflectionCounts(); v1Calls != 3 || alphaCalls != 0 {
		t.Fatalf("reflection calls v1=%d v1alpha=%d, want three TLS v1 requests", v1Calls, alphaCalls)
	}
}

func TestGRPCCompletionFallsBackToV1Alpha(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionV1Alpha, false)
	values, directive := completeGRPCCommand(t, address, "--plaintext", grpcFixtureServiceName+"/E")
	assertGRPCCompletion(t, values, grpcFixtureMethodName)
	assertGRPCCompletionDirective(t, directive)
	if _, alphaCalls := record.reflectionCounts(); alphaCalls != 2 {
		t.Fatalf("v1alpha reflection calls = %d, want list and descriptor fallback", alphaCalls)
	}
}

func TestGRPCCompletionRejectsUntrustedServiceNames(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionUntrustedNamesV1, false)
	values, directive := completeGRPCCommand(t, address, "--plaintext", "")
	assertGRPCCompletionDirective(t, directive)
	require.Len(t, values, 1)
	assertGRPCCompletion(t, values, grpcFixtureServiceName+"/")
}

func TestGRPCCompletionDoesNotPrepareCommandIO(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	root := newRootCmd()
	input := &countingReader{source: strings.NewReader(`{"text":"must not be read"}`)}
	root.SetIn(input)
	output := filepath.Join(t.TempDir(), "must-not-exist.json")

	values, directive, _ := completeGRPCCommandWithRoot(
		t,
		root,
		address,
		"--plaintext",
		"--input",
		"-",
		"--output",
		output,
		grpcFixtureServiceName+"/E",
	)
	assertGRPCCompletion(t, values, grpcFixtureMethodName)
	assertGRPCCompletionDirective(t, directive)
	require.Zero(t, input.reads.Load(), "stdin reads")
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("completion prepared output file: %v", err)
	}
	calls, _, _ := record.snapshot()
	require.Equal(t, 0, calls, "application RPC calls")
}

func TestGRPCCompletionRejectsInvalidOptionsLocally(t *testing.T) {
	t.Parallel()

	_, caPath, certPath, keyPath, _ := startGRPCMTLSFixture(t)
	tests := []struct {
		name  string
		flags []string
	}{
		{
			name:  "plaintext with custom CA",
			flags: []string{"--plaintext", "--ca", caPath},
		},
		{
			name:  "plaintext with server name",
			flags: []string{"--plaintext", "--servername", "fixture.test"},
		},
		{
			name:  "certificate without key",
			flags: []string{"--cert", certPath},
		},
		{
			name:  "key without certificate",
			flags: []string{"--key", keyPath},
		},
		{
			name:  "system roots without custom CA",
			flags: []string{"--system-ca"},
		},
		{
			name:  "negative timeout over TLS",
			flags: []string{"--timeout=-1s"},
		},
		{
			name:  "negative timeout over plaintext",
			flags: []string{"--plaintext", "--timeout=-1s"},
		},
		{
			name:  "invalid output format",
			flags: []string{"--plaintext", "--format", "yaml"},
		},
		{
			name:  "invalid output mode",
			flags: []string{"--plaintext", "--mode=rwx"},
		},
		{
			name:  "literal request over its size limit",
			flags: []string{"--plaintext", "--max-message-size", "1", "--data", `{"x":1}`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			root := newRootCmd()
			input := &countingReader{source: strings.NewReader("must not be read")}
			root.SetIn(input)
			output := filepath.Join(t.TempDir(), "must-not-exist")
			args := append([]string{address}, test.flags...)
			args = append(
				args,
				"--header", "authorization: Bearer rejected-completion",
				"--output", output,
				"fixture.",
			)

			values, directive, stderr := completeGRPCCommandWithRoot(t, root, args...)
			assert.Empty(t, values)
			if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
				t.Errorf("completion directive = %v, want no filename fallback", directive)
			}
			assertQuietGRPCCompletionFailure(t, stderr)
			assert.Zero(t, input.reads.Load(), "stdin reads")
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Errorf("invalid completion prepared output file: %v", err)
			}
			calls, callMetadata, reflectionMetadata := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if connections := record.connectionCount(); connections != 0 || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
				t.Errorf(
					"invalid completion reached network: connections=%d calls=%d reflection v1=%d v1alpha=%d",
					connections,
					calls,
					v1Calls,
					alphaCalls,
				)
			}
			if len(callMetadata) != 0 || len(reflectionMetadata) != 0 {
				t.Errorf("invalid completion sent metadata: call=%v reflection=%v", callMetadata, reflectionMetadata)
			}
		})
	}
}

func assertQuietGRPCCompletionFailure(t *testing.T, stderr string) {
	t.Helper()

	lower := strings.ToLower(stderr)
	for _, leaked := range []string{"connection refused", "deadline", "eof", "reflection", "unavailable"} {
		assert.NotContains(t, lower, leaked)
	}
}

func TestGRPCCompletionCredentialStdinIsQuietAndLiteralDashFileRemainsUsable(t *testing.T) { //nolint:paralleltest // isolates the literal dash file with Chdir
	address, caPath, record := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	ca, err := os.ReadFile(caPath)
	require.NoError(t, err)
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("-", ca, 0o600))
	for _, source := range []string{"-", "./-"} { //nolint:paralleltest // shares the working-directory fixture
		t.Run(source, func(t *testing.T) {
			root := newRootCmd()
			input := &countingReader{source: strings.NewReader("must not be read")}
			root.SetIn(input)
			output := filepath.Join(t.TempDir(), "must-not-exist")
			values, directive, stderr := completeGRPCCommandWithRoot(t, root, address, "--ca", source, "--output", output, grpcFixtureServiceName+"/E")
			assertGRPCCompletionDirective(t, directive)
			assertQuietGRPCCompletionFailure(t, stderr)
			if source == "-" {
				assert.Empty(t, values, "stdin credentials cannot be acquired during completion")
				assert.Zero(t, record.connectionCount(), "stdin credentials reached reflection network")
			} else {
				assertGRPCCompletion(t, values, grpcFixtureMethodName)
			}
			assert.Zero(t, input.reads.Load())
			_, statErr := os.Stat(output)
			assert.True(t, os.IsNotExist(statErr), "completion prepared output")
		})
	}
}

func TestGRPCTLSArtifactEncodingCompletion(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"ca", "cert", "key"} {
		values, directive := completeGRPCCommand(t, "--"+source+"-encoding", "ba")
		assert.Empty(t, values)
		assertGRPCCompletionDirective(t, directive)
		values, directive = completeGRPCCommand(t, "--"+source, "missing", "--"+source+"-encoding", "ba")
		candidates := strings.Join(values, "\n")
		assert.Contains(t, candidates, "base64")
		assert.Contains(t, candidates, "base32")
		assertGRPCCompletionDirective(t, directive)
		values, directive = completeGRPCCommand(t, "--plaintext", "--"+source, "missing", "--"+source+"-encoding", "ba")
		assert.Empty(t, values)
		assertGRPCCompletionDirective(t, directive)
	}
}

func TestGRPCCompletionFiltersContextualFlags(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		args     []string
		want     []string
		unwanted []string
	}{
		{
			name: "plaintext excludes TLS", args: []string{"--plaintext"},
			want: []string{"--data", "--input"}, unwanted: []string{"--ca", "--insecure", "--servername"},
		},
		{
			name: "last false permits TLS", args: []string{"--plaintext", "--plaintext=false"},
			want: []string{"--ca", "--insecure"},
		},
		{
			name: "missing key remains suggestible", args: []string{"--cert", "unread-client.pem"},
			want: []string{"--key"},
		},
		{
			name: "empty list still selects discovery", args: []string{"--list", ""},
			unwanted: []string{"--describe", "--template", "--data", "--input"},
		},
		{
			name: "template selects discovery", args: []string{"--template", grpcFixtureMethodName},
			unwanted: []string{"--list", "--describe", "--data", "--input"},
		},
		{
			name: "method selects invocation", args: []string{grpcFixtureMethodName},
			want: []string{"--data", "--input"}, unwanted: []string{"--list", "--describe", "--template"},
		},
		{
			name: "empty data still selects body", args: []string{"--data", ""},
			unwanted: []string{"--input", "--list", "--describe"},
		},
		{
			name: "file input excludes data", args: []string{"--input", "unread-request.json"},
			unwanted: []string{"--data", "--list", "--describe"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"127.0.0.1:1"}, test.args...)
			values, directive := completeGRPCCommand(t, append(args, "--")...)
			for _, want := range test.want {
				assertGRPCCompletion(t, values, want)
			}
			for _, unwanted := range test.unwanted {
				assertNoGRPCCompletion(t, values, unwanted)
			}
			assertGRPCCompletionDirective(t, directive)
		})
	}
}

func TestGRPCCompletionFiltersTypedValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "plaintext allows false replacement", args: []string{"--plaintext", "--insecure="}, want: []string{"false"}},
		{name: "CA excludes insecure true", args: []string{"--ca", "unread-ca.pem", "--insecure="}, want: []string{"false"}},
		{name: "CA excludes no-verify true", args: []string{"--ca", "unread-ca.pem", "--insecure-no-verify="}, want: []string{"false"}},
		{
			name: "empty CA allows plaintext values",
			args: []string{"--ca", "", "--plaintext="}, want: []string{"true", "false"},
		},
		{
			name: "last insecure false allows system CA before partner",
			args: []string{"--insecure", "--insecure=false", "--system-ca="}, want: []string{"true", "false"},
		},
		{name: "insecure blocks typed CA", args: []string{"--insecure", "--ca", ""}},
		{name: "no-verify blocks typed CA", args: []string{"--insecure-no-verify", "--ca", ""}},
		{name: "plaintext blocks typed key", args: []string{"--plaintext", "--key", ""}},
		{name: "empty list blocks typed input", args: []string{"--list", "", "--input", ""}},
		{name: "empty data blocks typed input", args: []string{"--data", "", "--input", ""}},
		{name: "template blocks typed input", args: []string{"--template", grpcFixtureMethodName, "--input", ""}},
		{name: "template formats only JSON", args: []string{"--template", grpcFixtureMethodName, "--format", ""}, want: []string{"json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values, directive := completeGRPCCommand(t, append([]string{"127.0.0.1:1"}, test.args...)...)
			if len(test.want) == 0 {
				assert.Empty(t, values)
			} else {
				assert.Equal(t, test.want, values)
			}
			assertGRPCCompletionDirective(t, directive)
		})
	}
}

func TestGRPCDataCompletionIsQuietWithoutAUsableTemplate(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	_, large, _ := grpcFixtureSchema(t)
	request := large.File[0].MessageType[0]
	for i := range 96 {
		request.Field = append(request.Field, &descriptorpb.FieldDescriptorProto{
			Name:   proto.String(fmt.Sprintf("long_template_field_name_%02d", i)),
			Number: proto.Int32(int32(100 + i)),
			Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
		})
	}
	largeProtoset := writeGRPCFixtureProtoset(t, large)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "no method", args: []string{"--protoset", protoset, "--data", ""}},
		{name: "missing method", args: []string{"--protoset", protoset, grpcFixtureServiceName + "/Missing", "--data", ""}},
		{name: "streaming method", args: []string{"--protoset", protoset, grpcFixtureServiceName + "/Watch", "--data", ""}},
		{name: "input owns the request", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--input", "unread.json", "--data", ""}},
		{name: "list conflicts", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--list", grpcFixtureServiceName, "--data", ""}},
		{name: "describe conflicts", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--describe", grpcFixtureServiceName, "--data", ""}},
		{name: "template conflicts", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--template", grpcFixtureMethodName, "--data", ""}},
		{name: "auth file from stdin", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--auth-bearer-file", "-", "--data", ""}},
		{name: "CA from stdin", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--ca", "-", "--data", ""}},
		{name: "unrelated prefix", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--data", `{"other`}},
		{name: "template larger than 2 KiB", args: []string{"--protoset", largeProtoset, grpcFixtureMethodName, "--data", ""}},
		{name: "invalid header", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--header", "bad header", "--data", ""}},
		{name: "missing CA", args: []string{"--protoset", protoset, grpcFixtureMethodName, "--ca", missing, "--data", ""}},
		// pflag reads -td as --timeout=d, which execution rejects.
		{name: "shorthand cluster value", args: []string{"--protoset", protoset, grpcFixtureMethodName, "-td", ""}},
		{name: "shorthand cluster inline value", args: []string{"--protoset", protoset, grpcFixtureMethodName, "-td="}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values, directive := completeGRPCCommand(t, append([]string{"127.0.0.1:1"}, test.args...)...)
			assert.Empty(t, values)
			assertGRPCCompletionDirective(t, directive)
		})
	}
	values, _ := completeGRPCCommand(t, "127.0.0.1:1", "--protoset", protoset, grpcFixtureMethodName, "--data", `'{"te`)
	assert.Len(t, values, 1, "an opening shell quote still matches the template")
}

func TestGRPCProtosetCompletionFollowsExecutionValidation(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	oversizedToken := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(oversizedToken, []byte(strings.Repeat("t", 64<<10+1)), 0o600))
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "invalid header", args: []string{"--header", "bad header", grpcFixtureServiceName + "/"}},
		{name: "invocation loads a missing CA", args: []string{"--ca", missing, grpcFixtureServiceName + "/"}},
		{name: "output replaces the protoset", args: []string{"--output", protoset, "--list", ""}},
		{name: "invalid output encoding", args: []string{"--encoding", "bogus", "--describe", ""}},
		{name: "output mode without an output file", args: []string{"--mode", "0600", "--list", ""}},
		{name: "credential file over its size limit", args: []string{"--auth-bearer-file", oversizedToken, "--list", ""}},
		{
			name: "inline value after a dash-led literal",
			args: []string{"--auth-bearer", "-v", "--list="},
			want: []string{grpcFixtureServiceName},
		},
		// Protoset discovery never dials, so execution does not read the CA.
		{name: "discovery ignores a missing CA", args: []string{"--ca", missing, "--list", ""}, want: []string{grpcFixtureServiceName}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values, directive := completeGRPCCommand(t, append([]string{"127.0.0.1:1", "--protoset", protoset}, test.args...)...)
			var names []string
			for _, value := range values {
				name, _, _ := strings.Cut(value, "\t")
				names = append(names, name)
			}
			assert.Equal(t, test.want, names)
			assertGRPCCompletionDirective(t, directive)
		})
	}
}

func TestGRPCDataCompletionFollowsShorthandClusters(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	// pflag consumes boolean shorthands, so -vd means --verbose --data.
	for _, words := range [][]string{{"-d", ""}, {"-d="}, {"-vd", ""}, {"-vd="}} {
		t.Run(strings.Join(words, " "), func(t *testing.T) {
			t.Parallel()
			args := append([]string{"127.0.0.1:1", "--protoset", protoset, grpcFixtureMethodName}, words...)
			values, directive := completeGRPCCommand(t, args...)
			assert.Len(t, values, 1, "completion of %q", words)
			assertGRPCCompletionDirective(t, directive)
		})
	}
}

func TestGRPCCompletionLiteralValuesDoNotOfferFiles(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--data", "--header", "--max-message-size", "--servername", "--timeout"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			_, directive := completeGRPCCommand(t, "127.0.0.1:1", flag, "")
			assertGRPCCompletionDirective(t, directive)
		})
	}
}

func TestGRPCCompletionPreservesReusedRootReferenceHelp(t *testing.T) {
	t.Parallel()
	helpArgs := []string{"grpc", "127.0.0.1:1", "--plaintext", "--help"}
	freshHelp, _, err := executeRootStreams(t, helpArgs...)
	require.NoError(t, err)
	root := newRootCmd()
	_, directive, _ := completeGRPCCommandWithRoot(t, root, "127.0.0.1:1", "--plaintext", "--")
	assertGRPCCompletionDirective(t, directive)
	reusedHelp, _, err := executeRootCommandStreams(t, root, helpArgs...)
	require.NoError(t, err)
	assert.Equal(t, freshHelp, reusedHelp, "completion must preserve ordinary reference help")
}
