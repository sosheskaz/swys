package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestGRPCDiscoverySelectors(t *testing.T) {
	t.Parallel()

	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	tests := []struct {
		name       string
		args       []string
		want       []string
		wantJSON   bool
		shouldFail bool
	}{
		{name: "list methods", args: []string{"grpc", address, "--plaintext", "--list", grpcFixtureServiceName}, want: []string{"Echo", "Watch"}},
		{
			name: "describe message",
			args: []string{"grpc", address, "--plaintext", "--describe", "fixture.v1.EchoRequest"},
			want: []string{"EchoRequest", "payload", "labels"},
		},
		{name: "services JSON", args: []string{"grpc", address, "--plaintext", "--format", "json"}, want: []string{grpcFixtureServiceName}, wantJSON: true},
		{
			name:     "methods JSON",
			args:     []string{"grpc", address, "--plaintext", "--list", grpcFixtureServiceName, "--format", "json"},
			want:     []string{"Echo", "Watch"},
			wantJSON: true,
		},
		{
			name:     "describe JSON",
			args:     []string{"grpc", address, "--plaintext", "--describe", "fixture.v1.EchoRequest", "--format", "json"},
			want:     []string{"EchoRequest", "payload"},
			wantJSON: true,
		},
		{name: "missing service", args: []string{"grpc", address, "--plaintext", "--list", "fixture.v1.Missing"}, shouldFail: true},
		{name: "missing symbol", args: []string{"grpc", address, "--plaintext", "--describe", "fixture.v1.Missing"}, shouldFail: true},
		{
			name:       "mutually exclusive selectors",
			args:       []string{"grpc", address, "--plaintext", "--list", grpcFixtureServiceName, "--describe", "fixture.v1.EchoRequest"},
			shouldFail: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, test.args...)
			if test.shouldFail {
				if err == nil {
					t.Fatalf("command succeeded; stdout %q", stdout)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range test.want {
				if !strings.Contains(stdout, value) {
					t.Fatalf("output %q does not contain %q", stdout, value)
				}
			}
			if test.wantJSON && !json.Valid([]byte(stdout)) {
				t.Fatalf("output is not valid JSON: %q", stdout)
			}
		})
	}
}

func TestGRPCExplicitEmptyDiscoverySelectorsRejectBeforeNetwork(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "empty list", args: []string{"--list", ""}},
		{name: "empty describe", args: []string{"--describe", ""}},
		{name: "empty list conflicts with describe", args: []string{"--list", "", "--describe", "fixture.v1.EchoRequest"}},
		{name: "list conflicts with empty describe", args: []string{"--list", grpcFixtureServiceName, "--describe", ""}},
		{name: "empty protoset", args: []string{"--protoset", ""}},
		{name: "input without method", args: []string{"--input", filepath.Join(t.TempDir(), "missing.json")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			args := append([]string{"grpc", address, "--plaintext"}, test.args...)
			_, _, err := executeRootStreams(t, args...)
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if err == nil || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
				t.Fatalf(
					"error=%v calls=%d reflection v1=%d v1alpha=%d, want local rejection",
					err, calls, v1Calls, alphaCalls,
				)
			}
		})
	}
}

func TestGRPCCommandContract(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	command, _, err := root.Find([]string{"grpc"})
	if err != nil || command == nil || command.Name() != "grpc" {
		t.Fatalf("find grpc command: command=%v error=%v", command, err)
	}
	for _, test := range []struct {
		name      string
		shorthand string
		value     string
	}{
		{name: "header", shorthand: "H"},
		{name: "verbose", shorthand: "v"},
		{name: "timeout", value: "10s"},
	} {
		flag := command.Flags().Lookup(test.name)
		if flag == nil {
			flag = command.PersistentFlags().Lookup(test.name)
		}
		if flag == nil {
			t.Fatalf("--%s is missing", test.name)
		}
		if flag.Shorthand != test.shorthand {
			t.Fatalf("--%s shorthand = %q, want %q", test.name, flag.Shorthand, test.shorthand)
		}
		if test.value != "" && flag.DefValue != test.value {
			t.Fatalf("--%s default = %q, want %q", test.name, flag.DefValue, test.value)
		}
	}
}

func TestGRPCReflectionFallsBackToV1Alpha(t *testing.T) {
	t.Parallel()
	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionV1Alpha, false)
	stdout, _, err := executeRootStreams(t, "grpc", address, "--plaintext")
	if err != nil {
		t.Fatalf("v1alpha-only reflection: %v", err)
	}
	if !strings.Contains(stdout, grpcFixtureServiceName) {
		t.Fatalf("service listing %q does not contain fixture", stdout)
	}
}

func TestGRPCReflectionDoesNotFallbackOnNonUnimplementedStatus(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionDeniedV1WithAlpha, false)
	_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "--timeout", "250ms")
	if err == nil {
		t.Fatal("v1 PermissionDenied incorrectly fell back to v1alpha")
	}
	if status.Code(err) != codes.PermissionDenied && !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Fatalf("error = %v, want v1 PermissionDenied", err)
	}
	v1Calls, alphaCalls := record.reflectionCounts()
	if v1Calls != 1 || alphaCalls != 0 {
		t.Fatalf("reflection calls v1=%d v1alpha=%d, want 1 and 0", v1Calls, alphaCalls)
	}
}

func TestGRPCReflectionDoesNotWaitForServerToCloseAfterValidResponse(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name           string
		reflectionMode grpcFixtureReflection
		wantV1         int
		wantV1Alpha    int
	}{
		{name: "v1", reflectionMode: grpcFixtureReflectionOpenV1, wantV1: 1},
		{name: "v1alpha fallback", reflectionMode: grpcFixtureReflectionOpenV1Alpha, wantV1Alpha: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, test.reflectionMode, false)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			root := newRootCmd()
			root.SetContext(ctx)
			type commandResult struct {
				err    error
				stdout string
				stderr string
			}
			result := make(chan commandResult, 1)
			go func() {
				stdout, stderr, err := executeRootCommandStreams(
					t,
					root,
					"grpc", address, "--plaintext", "--timeout", "0",
				)
				result <- commandResult{stdout: stdout, stderr: stderr, err: err}
			}()

			select {
			case <-record.reflectionResponseSent:
			case <-ctx.Done():
				t.Fatal("fixture did not send its valid reflection response before the safeguard deadline")
			}

			var command commandResult
			select {
			case command = <-result:
			case <-ctx.Done():
				select {
				case command = <-result:
					t.Fatalf("command waited for reflection stream closure: error=%q", command.err)
				case <-time.After(time.Second):
					t.Fatal("command did not stop after its outer context was canceled")
				}
			}
			if command.err != nil {
				t.Fatalf("invoke after valid open reflection response: %v", command.err)
			}
			if !strings.Contains(command.stdout, grpcFixtureServiceName) || command.stderr != "" {
				t.Fatalf("stdout=%q stderr=%q, want discovery response only", command.stdout, command.stderr)
			}
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if calls != 0 || v1Calls != test.wantV1 || alphaCalls != test.wantV1Alpha {
				t.Fatalf(
					"calls=%d reflection v1=%d v1alpha=%d, want unary=0 v1=%d v1alpha=%d",
					calls, v1Calls, alphaCalls, test.wantV1, test.wantV1Alpha,
				)
			}
			select {
			case <-record.reflectionContextDone:
			case <-time.After(time.Second):
				t.Fatal("open reflection fixture did not observe client cleanup")
			}
		})
	}
}

func TestGRPCReflectionCancellationReturnsParentContextError(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	root := newRootCmd()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	root.SetContext(ctx)
	result := make(chan error, 1)
	go func() {
		_, _, err := executeRootCommandStreams(
			t,
			root,
			"grpc", address, "--plaintext", "--timeout", "0",
		)
		result <- err
	}()

	select {
	case <-record.reflectionStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not start reflection")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want parent %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not return after parent cancellation")
	}
	select {
	case <-record.reflectionContextDone:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not reach reflection stream")
	}
	calls, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("parent cancellation invoked unary service %d times", calls)
	}
}

func TestGRPCReflectionEOFWithLiveContextRemainsEOF(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionEOFV1, false)
	_, _, err := executeRootStreams(
		t,
		"grpc", address, "--plaintext", "--timeout", "0",
	)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want live reflection stream %v", err, io.EOF)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("live reflection stream error = %v, do not want %v", err, context.Canceled)
	}
	calls, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("live reflection EOF invoked unary service %d times", calls)
	}
}

func TestDialGRPCCanonicalTargetUsesDNSNamespaceForHostPort(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"localhost:443",
		"127.0.0.1:50051",
		"[::1]:8443",
		"[fe80::1%lo0]:8443",
		"unix:1234",
		"dns:5000",
		"passthrough:1234",
	} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			connection, _, err := dialGRPC(&cobra.Command{}, endpoint, &grpcOptions{plaintext: true})
			if err != nil {
				t.Fatalf("dial valid host:port endpoint %q: %v", endpoint, err)
			}
			t.Cleanup(func() {
				if err := connection.Close(); err != nil {
					t.Errorf("close gRPC client: %v", err)
				}
			})

			canonical := connection.CanonicalTarget()
			if want := "dns:///" + endpoint; canonical != want {
				t.Fatalf("CanonicalTarget() = %q, want %q", canonical, want)
			}
		})
	}
}

func TestGRPCReflectionDetailsReadsTrailersOnlyAfterReceiveError(t *testing.T) {
	t.Parallel()

	header := metadata.Pairs("fixture-reflection-header", "seen")
	trailer := metadata.Pairs("fixture-reflection-trailer", "done")
	for _, test := range []struct {
		receiveErr      error
		name            string
		wantTrailerCall bool
		wantStatus      codes.Code
	}{
		{name: "successful receive", wantStatus: codes.OK},
		{
			name:            "terminal receive error",
			receiveErr:      status.Error(codes.Unavailable, "reflection ended"),
			wantTrailerCall: true,
			wantStatus:      codes.Unavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var trailerCalls atomic.Int32
			details := grpcReflectionDetails(
				func() (metadata.MD, error) { return header, nil },
				func() metadata.MD {
					trailerCalls.Add(1)
					return trailer
				},
				peer.Peer{},
				test.receiveErr,
			)
			if got := trailerCalls.Load(); (got != 0) != test.wantTrailerCall {
				t.Fatalf("trailer callback calls = %d, want called=%t", got, test.wantTrailerCall)
			}
			if !reflect.DeepEqual(details.header, header) {
				t.Fatalf("header = %v, want %v", details.header, header)
			}
			if test.wantTrailerCall {
				if !reflect.DeepEqual(details.trailer, trailer) {
					t.Fatalf("trailer = %v, want %v", details.trailer, trailer)
				}
			} else if details.trailer != nil {
				t.Fatalf("trailer = %v, want unavailable before terminal receive error", details.trailer)
			}
			if details.status.Code() != test.wantStatus {
				t.Fatalf("status = %v, want %v", details.status.Code(), test.wantStatus)
			}
		})
	}
}

func TestGRPCEndpointRejectsControlCharacters(t *testing.T) {
	t.Parallel()
	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, test := range []struct {
		name     string
		endpoint string
		valid    bool
	}{
		{name: "DNS", endpoint: "localhost:443", valid: true},
		{name: "IPv4", endpoint: "127.0.0.1:1", valid: true},
		{name: "IPv6", endpoint: "[::1]:8443", valid: true},
		{name: "NUL", endpoint: "\x00:1"},
		{name: "reported control", endpoint: "\x03:4"},
		{name: "DEL", endpoint: "\x7f:443"},
		{name: "ASCII whitespace", endpoint: "local host:443"},
		{name: "Unicode whitespace", endpoint: "local\u00a0host:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := executeRootStreams(t, "grpc", test.endpoint, "--protoset", protoset)
			if test.valid {
				if err != nil {
					t.Fatalf("valid endpoint %q rejected: %v", test.endpoint, err)
				}
				return
			}
			if !errors.Is(err, errInvalidGRPCOptions) {
				t.Fatalf("endpoint %q error = %v, want errInvalidGRPCOptions", test.endpoint, err)
			}
		})
	}
}

func TestGRPCRejectsInvalidAndReservedMetadataBeforeNetwork(t *testing.T) {
	t.Parallel()
	for _, header := range []string{
		"Bad_Key: value",
		"x-test: good\nbad",
		"x-test: tab\tvalue",
		"x-test:\rvalue",
		"x-test:\nvalue",
		"x-test:\tvalue",
		"x-test: value\r",
		"x-test: value\n",
		"x-test: value\t",
		"x-test-bin: ***",
		":authority: example.test",
		"grpc-timeout: 1S",
		"content-type: application/grpc",
		"te: trailers",
		"connection: close",
		"keep-alive: timeout=5",
		"proxy-connection: close",
		"transfer-encoding: chunked",
		"upgrade: websocket",
		"host: example.test",
	} {
		t.Run(fmt.Sprintf("%q", header), func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "-H", header)
			connections := record.connectionCount()
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if err == nil || connections != 0 || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
				t.Fatalf(
					"error=%v connections=%d calls=%d reflection v1=%d v1alpha=%d, want local rejection",
					err, connections, calls, v1Calls, alphaCalls,
				)
			}
		})
	}
}

func TestGRPCRejectsNonASCIIApplicationMetadataBeforeNetwork(t *testing.T) {
	t.Parallel()
	for _, header := range []string{
		"x-test: \x99",
		"x-test: café",
	} {
		t.Run(fmt.Sprintf("%q", header), func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			_, _, err := executeRootStreams(
				t,
				"grpc", address, "--plaintext", "-H", header,
			)
			connections := record.connectionCount()
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if !errors.Is(err, errInvalidGRPCMetadata) || connections != 0 || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
				t.Fatalf(
					"error=%v connections=%d calls=%d reflection v1=%d v1alpha=%d, want local invalid-metadata rejection",
					err, connections, calls, v1Calls, alphaCalls,
				)
			}
		})
	}
}

func TestGRPCTLSDefaultsAndPlaintextOptOut(t *testing.T) {
	t.Parallel()

	t.Run("verified TLS default", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		stdout, _, err := executeRootStreams(t, "grpc", address, "--ca", caPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, grpcFixtureServiceName) {
			t.Fatalf("TLS discovery response = %q", stdout)
		}
	})

	t.Run("default refuses plaintext server", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, _, err := executeRootStreams(t, "grpc", address, "--timeout", "500ms")
		if err == nil {
			t.Fatal("TLS default connected to plaintext server")
		}
		calls, _ := record.snapshot()
		if calls != 0 {
			t.Fatalf("plaintext service calls = %d", calls)
		}
	})

	t.Run("plaintext conflicts with TLS controls", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "--ca", caPath)
		if err == nil {
			t.Fatal("--plaintext with --ca succeeded")
		}
		calls, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("conflicting transport options reached network")
		}
	})

	t.Run("insecure TLS", func(t *testing.T) {
		t.Parallel()
		address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, "--insecure")
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("server name and combined roots", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, "--ca", caPath, "--system-ca", "--servername", "localhost")
		if err != nil {
			t.Fatal(err)
		}
	})
}

//nolint:paralleltest,tparallel // Subtests intentionally share one mTLS server and cumulative recorder.
func TestGRPCMutualTLSRequiresClientCertificatePair(t *testing.T) {
	t.Parallel()
	address, caPath, certPath, keyPath, record := startGRPCMTLSFixture(t)

	t.Run("server rejects missing client certificate", func(t *testing.T) {
		_, _, err := executeRootStreams(t, "grpc", address, "--ca", caPath, "--timeout", "500ms")
		if err == nil {
			t.Fatal("mTLS server accepted a client without a certificate pair")
		}
		calls, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("unauthenticated client reached gRPC: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
		}
	})

	t.Run("client rejects incomplete certificate pair", func(t *testing.T) {
		_, _, err := executeRootStreams(t, "grpc", address, "--ca", caPath, "--cert", certPath, "--timeout", "500ms")
		if err == nil {
			t.Fatal("--cert without --key succeeded")
		}
		calls, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("incomplete client pair reached gRPC: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
		}
	})

	t.Run("client certificate pair succeeds", func(t *testing.T) {
		stdout, _, err := executeRootStreams(t, "grpc", address, "--ca", caPath, "--cert", certPath, "--key", keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, grpcFixtureServiceName) {
			t.Fatalf("mTLS discovery response = %q", stdout)
		}
		calls, _ := record.snapshot()
		if calls != 0 {
			t.Fatalf("authenticated calls = %d, want zero", calls)
		}
	})
}

func TestGRPCTimeoutBoundsHangingReflection(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	started := time.Now()
	stdout, stderr, err := executeRootStreams(t, "grpc", address, "--plaintext", "--timeout", "1s")
	if err == nil {
		t.Fatal("hanging reflection succeeded")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("reflection timeout returned after %s", elapsed)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "deadline") {
		t.Fatalf("error = %v, want deadline diagnostic", err)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("reflection timeout output stdout=%q stderr=%q, want none", stdout, stderr)
	}
	v1Calls, alphaCalls := record.reflectionCounts()
	if v1Calls != 1 || alphaCalls != 0 {
		t.Fatalf("reflection calls v1=%d v1alpha=%d, want 1 and 0", v1Calls, alphaCalls)
	}
}

func TestGRPCTimeoutZeroDisablesDeadline(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "--timeout", "0")
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := record.snapshot()
	if calls != 0 {
		t.Fatalf("calls = %d, want zero", calls)
	}
}

func TestGRPCVerboseReportsStatusMetadataAndTLS(t *testing.T) {
	t.Parallel()

	t.Run("verified discovery", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", address, "--ca", caPath, "--verbose",
		)
		if err != nil {
			t.Fatal(err)
		}
		requireGRPCDiagnosticValues(t, stderr, "OK", "fixture-reflection-header", "seen")
		requireGRPCTLSFacts(t, stderr, true)
	})

	t.Run("insecure discovery reports unverified state", func(t *testing.T) {
		t.Parallel()
		address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", address, "--insecure", "--verbose",
		)
		if err != nil {
			t.Fatal(err)
		}
		requireGRPCTLSFacts(t, stderr, false)
	})

	t.Run("offline discovery does not fabricate TLS", func(t *testing.T) {
		t.Parallel()
		_, set, _ := grpcFixtureSchema(t)
		protoset := writeGRPCFixtureProtoset(t, set)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", "127.0.0.1:1", "--protoset", protoset, "--verbose",
		)
		if err != nil {
			t.Fatal(err)
		}
		requireGRPCDiagnosticValues(t, stderr, "OK")
		lower := strings.ToLower(stderr)
		for _, unavailable := range []string{"version", "cipher", "verified"} {
			if strings.Contains(lower, unavailable) {
				t.Fatalf("offline diagnostics fabricate %q: %q", unavailable, stderr)
			}
		}
	})
}

func requireGRPCDiagnosticValues(t *testing.T, diagnostics string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(strings.ToLower(diagnostics), strings.ToLower(value)) {
			t.Fatalf("diagnostics %q do not contain %q", diagnostics, value)
		}
	}
}

func requireGRPCTLSFacts(t *testing.T, diagnostics string, verified bool) {
	t.Helper()
	requireGRPCDiagnosticValues(t, diagnostics, "TLS", "version", "cipher")
	lower := strings.ToLower(diagnostics)
	if verified {
		for _, value := range []string{"verified=true", "verification enabled", "certificate verified"} {
			if strings.Contains(lower, value) {
				return
			}
		}
		t.Fatalf("diagnostics %q do not identify verified TLS", diagnostics)
	}
	for _, value := range []string{"verified=false", "verification disabled", "unverified", "insecure"} {
		if strings.Contains(lower, value) {
			return
		}
	}
	t.Fatalf("diagnostics %q do not identify disabled TLS verification", diagnostics)
}

func TestGRPCReflectionAcceptsSchemaAboveDefaultReceiveLimit(t *testing.T) {
	t.Parallel()

	const descriptorSize = 4<<20 + 1024
	_, set, _ := grpcFixtureSchema(t)
	grpcFixturePadFileToSerializedSize(t, set.File[0], descriptorSize)
	files, request := grpcFixtureDescriptorsFromSet(t, set)

	aggregateSize := 0
	for _, file := range set.File {
		aggregateSize += proto.Size(file)
	}
	if aggregateSize <= 4<<20 || aggregateSize >= 16<<20 {
		t.Fatalf("fixture descriptor aggregate = %d, want between 4 MiB and 16 MiB", aggregateSize)
	}

	for _, test := range []struct {
		name           string
		reflectionMode grpcFixtureReflection
		wantV1         int
		wantV1Alpha    int
	}{
		{name: "v1", reflectionMode: grpcFixtureReflectionV1, wantV1: 1},
		{name: "v1alpha fallback", reflectionMode: grpcFixtureReflectionV1Alpha, wantV1Alpha: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, record := startGRPCFixtureWithSchema(t, test.reflectionMode, nil, files, set, request)
			stdout, _, err := executeRootStreams(
				t,
				"grpc", address, "--plaintext", "--describe", "fixture.v1.EchoRequest",
			)
			if err != nil {
				t.Fatalf("describe through valid %d-byte reflected schema: %v", aggregateSize, err)
			}
			if !strings.Contains(stdout, "EchoRequest") {
				t.Fatalf("response = %q, want reflected request descriptor", stdout)
			}
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if calls != 0 || v1Calls != test.wantV1 || alphaCalls != test.wantV1Alpha {
				t.Fatalf(
					"calls=%d reflection v1=%d v1alpha=%d, want unary=0 v1=%d v1alpha=%d",
					calls, v1Calls, alphaCalls, test.wantV1, test.wantV1Alpha,
				)
			}
		})
	}
}

func TestGRPCBinaryMetadataUsesStandardBase64(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	value := []byte{0, 1, 2, 0xff}
	_, _, err := executeRootStreams(
		t,
		"grpc", address, "--plaintext",
		"-H", "sample-bin: "+base64.StdEncoding.EncodeToString(value),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, md := record.snapshot()
	if got := md.Get("sample-bin"); len(got) != 1 || !bytes.Equal([]byte(got[0]), value) {
		t.Fatalf("binary metadata = %q, want %x", got, value)
	}
}
