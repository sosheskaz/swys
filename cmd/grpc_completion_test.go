package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestGRPCCompletionUsesSeparateTwoSecondDeadline(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	started := time.Now()
	values, directive := completeGRPCCommand(t, address, "--plaintext", "--timeout", "50ms", "")
	elapsed := time.Since(started)

	if len(values) != 0 {
		t.Fatalf("timed-out completion = %q, want no candidates", values)
	}
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

	if len(values) != 0 {
		t.Fatalf("canceled completion = %q, want no candidates", values)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	refusedAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
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
			if len(values) != 0 {
				t.Fatalf("failed completion = %q, want no candidates", values)
			}
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
	if got := commandMetadata.Get("authorization"); !slices.Equal(got, []string{authorization}) {
		t.Fatalf("command authorization = %q, want one metadata value", got)
	}
	if got := commandMetadata.Get("x-completion-test"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("command repeated metadata = %q, want both values once and in order", got)
	}

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
	if got := listMetadata.Get("authorization"); !slices.Equal(got, []string{authorization}) {
		t.Fatalf("list reflection authorization = %q, want propagated metadata", got)
	}
	if got := listMetadata.Get("x-completion-test"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("list reflection repeated metadata = %q, want both values once and in order", got)
	}

	methodArgs := append([]string{address}, flags...)
	methods, _ := completeGRPCCommand(t, append(methodArgs, grpcFixtureServiceName+"/E")...)
	assertGRPCCompletion(t, methods, grpcFixtureMethodName)
	calls, _, descriptorMetadata := record.snapshot()
	if got := descriptorMetadata.Get("authorization"); !slices.Equal(got, []string{authorization}) {
		t.Fatalf("descriptor reflection authorization = %q, want propagated metadata", got)
	}
	if got := descriptorMetadata.Get("x-completion-test"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("descriptor reflection repeated metadata = %q, want both values once and in order", got)
	}
	if calls != 0 {
		t.Fatalf("authenticated completion invoked %d application RPCs, want none", calls)
	}
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
	if !slices.Equal(values, []string{grpcFixtureServiceName + "/"}) {
		t.Fatalf("completion from untrusted service names = %q, want only the valid service", values)
	}
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
	if reads := input.reads.Load(); reads != 0 {
		t.Fatalf("completion read stdin %d times, want none", reads)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("completion prepared output file: %v", err)
	}
	calls, _, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("completion invoked %d application RPCs, want none", calls)
	}
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
			if len(values) != 0 {
				t.Errorf("invalid TLS completion = %q, want no candidates", values)
			}
			if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
				t.Errorf("completion directive = %v, want no filename fallback", directive)
			}
			assertQuietGRPCCompletionFailure(t, stderr)
			if reads := input.reads.Load(); reads != 0 {
				t.Errorf("invalid TLS completion read stdin %d times", reads)
			}
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
		if strings.Contains(lower, leaked) {
			t.Fatalf("completion stderr = %q, leaked failure detail %q", stderr, leaked)
		}
	}
}
