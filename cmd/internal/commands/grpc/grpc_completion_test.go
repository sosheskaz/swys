package grpc_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.Equal(t, []string{grpcFixtureServiceName + "/"}, values)
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

func TestGRPCCompletionRejectsInvalidTLSFlagCombinationsLocally(t *testing.T) {
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
			name:  "insecure with custom CA",
			flags: []string{"--insecure", "--ca", caPath},
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
				t.Errorf("invalid TLS completion prepared output file: %v", err)
			}
			calls, callMetadata, reflectionMetadata := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if connections := record.connectionCount(); connections != 0 || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
				t.Errorf(
					"invalid TLS completion reached network: connections=%d calls=%d reflection v1=%d v1alpha=%d",
					connections,
					calls,
					v1Calls,
					alphaCalls,
				)
			}
			if len(callMetadata) != 0 || len(reflectionMetadata) != 0 {
				t.Errorf("invalid TLS completion sent metadata: call=%v reflection=%v", callMetadata, reflectionMetadata)
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
