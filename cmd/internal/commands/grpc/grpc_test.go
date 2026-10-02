package grpc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	grpccommand "github.com/sosheskaz-systems/npc/cmd/internal/commands/grpc"
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
		{
			name:       "method conflicts with list",
			args:       []string{"grpc", address, grpcFixtureMethodName, "--plaintext", "--list", grpcFixtureServiceName},
			shouldFail: true,
		},
		{
			name:       "method conflicts with describe",
			args:       []string{"grpc", address, grpcFixtureMethodName, "--plaintext", "--describe", "fixture.v1.EchoRequest"},
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
			require.NoError(t, err)
			for _, value := range test.want {
				assert.Contains(t, stdout, value)
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
		{name: "empty method", args: []string{""}},
		{name: "empty list", args: []string{"--list", ""}},
		{name: "empty describe", args: []string{"--describe", ""}},
		{name: "empty list conflicts with describe", args: []string{"--list", "", "--describe", "fixture.v1.EchoRequest"}},
		{name: "list conflicts with empty describe", args: []string{"--list", grpcFixtureServiceName, "--describe", ""}},
		{name: "method conflicts with empty list", args: []string{grpcFixtureMethodName, "--list", ""}},
		{name: "method conflicts with empty describe", args: []string{grpcFixtureMethodName, "--describe", ""}},
		{name: "empty protoset", args: []string{"--protoset", ""}},
		{name: "data without method", args: []string{"--data", "{"}},
		{name: "input without method", args: []string{"--input", filepath.Join(t.TempDir(), "missing.json")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			args := append([]string{"grpc", address, "--plaintext"}, test.args...)
			_, _, err := executeRootStreams(t, args...)
			calls, _, _ := record.snapshot()
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
	require.NoError(t, err)
	require.NotNil(t, command)
	require.Equal(t, "grpc", command.Name())
	for _, test := range []struct {
		name      string
		shorthand string
		value     string
	}{
		{name: "data", shorthand: "d"},
		{name: "header", shorthand: "H"},
		{name: "verbose", shorthand: "v"},
		{name: "encoding", shorthand: "e", value: "raw"},
		{name: "timeout", value: "10s"},
		{name: "max-message-size", value: "16777216"},
	} {
		flag := command.Flags().Lookup(test.name)
		if flag == nil {
			flag = command.PersistentFlags().Lookup(test.name)
		}
		require.NotNil(t, flag, "--%s", test.name)
		require.Equal(t, test.shorthand, flag.Shorthand, "--%s shorthand", test.name)
		if test.value != "" {
			require.Equal(t, test.value, flag.DefValue, "--%s default", test.name)
		}
	}
}

func TestGRPCInvalidOutputOptionsPreserveFileAndAvoidInvocation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		wantErr error
		name    string
		flag    string
		value   string
	}{
		{name: "format", flag: "--format", value: "invalid-output-option", wantErr: errInvalidGRPCOptions},
		{name: "empty format", flag: "--format", value: "", wantErr: errInvalidGRPCOptions},
		{name: "encoding", flag: "--encoding", value: "invalid-output-option", wantErr: encoding.ErrUnknownOutputEncoding},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			output := filepath.Join(t.TempDir(), "response")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))

			_, _, err := executeRootStreams(t,
				"grpc", address, grpcFixtureMethodName, "--plaintext", "--data", `{}`,
				test.flag, test.value, "--output", output,
			)
			require.ErrorIs(t, err, test.wantErr)
			calls, _, _ := record.snapshot()
			assert.Zero(t, calls, "invalid output option must not invoke the application RPC")
			content, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(content), "invalid output option must not truncate the file")
		})
	}
}

func TestGRPCReflectionFallsBackToV1Alpha(t *testing.T) {
	t.Parallel()
	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionV1Alpha, false)
	stdout, _, err := executeRootStreams(t, "grpc", address, "--plaintext")
	require.NoError(t, err, "v1alpha-only reflection: %v", err)
	assert.Contains(t, stdout, grpcFixtureServiceName)
}

func TestGRPCReflectionHalfClosesRequestBeforeWaitingForResponse(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name           string
		wantOutput     string
		selector       []string
		reflectionMode grpcFixtureReflection
	}{
		{
			name:           "v1 service discovery",
			reflectionMode: grpcFixtureReflectionEOFBeforeResponseV1,
			wantOutput:     grpcFixtureServiceName,
		},
		{
			name:           "v1 symbol discovery",
			reflectionMode: grpcFixtureReflectionEOFBeforeResponseV1,
			selector:       []string{"--describe", "fixture.v1.EchoRequest"},
			wantOutput:     "EchoRequest",
		},
		{
			name:           "v1alpha symbol fallback",
			reflectionMode: grpcFixtureReflectionEOFBeforeResponseV1Alpha,
			selector:       []string{"--describe", "fixture.v1.EchoRequest"},
			wantOutput:     "EchoRequest",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, test.reflectionMode, false)
			args := []string{"grpc", address, "--plaintext", "--timeout", "500ms"}
			args = append(args, test.selector...)
			stdout, _, err := executeRootStreams(t, args...)

			observedRequestEOF := false
			select {
			case <-record.reflectionRequestEOF:
				observedRequestEOF = true
			default:
			}
			if err != nil {
				v1Calls, alphaCalls := record.reflectionCounts()
				t.Fatalf(
					"reflection failed before response after request EOF=%t (calls v1=%d v1alpha=%d): %v",
					observedRequestEOF,
					v1Calls,
					alphaCalls,
					err,
				)
			}
			if !observedRequestEOF {
				t.Fatal("fixture responded without observing EOF on the reflection request stream")
			}
			assert.Contains(t, stdout, test.wantOutput)
		})
	}
}

func TestGRPCReflectionDoesNotFallbackOnNonUnimplementedStatus(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionDeniedV1WithAlpha, false)
	_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "--timeout", "250ms")
	require.Error(t, err)
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
					"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "0", "-d", `{}`,
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
			if strings.TrimSpace(command.stdout) != "{}" || command.stderr != "" {
				t.Fatalf("stdout=%q stderr=%q, want unary response only", command.stdout, command.stderr)
			}
			calls, _, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if calls != 1 || v1Calls != test.wantV1 || alphaCalls != test.wantV1Alpha {
				t.Fatalf(
					"calls=%d reflection v1=%d v1alpha=%d, want unary=1 v1=%d v1alpha=%d",
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

func TestGRPCProtobufJSONSemantics(t *testing.T) {
	t.Parallel()
	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	request := `{"payload":"AAEC","count":"9223372036854775807","mode":"MODE_ACTIVE",` +
		`"tags":["first","second"],"labels":{"a":1,"b":2},"id":7,` +
		`"extra":{"@type":"type.googleapis.com/google.protobuf.StringValue","value":"inside"}}`
	stdout, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--format", "json", "-d", request)
	require.NoError(t, err)
	var response map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &response), "decode response: %v", err)
	if response["payload"] != "AAEC" || response["count"] != "9223372036854775807" || response["mode"] != "MODE_ACTIVE" {
		t.Fatalf("scalar protobuf JSON mismatch: %#v", response)
	}
	if response["id"] != float64(7) {
		t.Fatalf("oneof response = %#v", response)
	}
	extra, ok := response["extra"].(map[string]any)
	if !ok || extra["@type"] != "type.googleapis.com/google.protobuf.StringValue" || extra["value"] != "inside" {
		t.Fatalf("Any response = %#v", response["extra"])
	}
}

func TestGRPCRequestJSONIsStrictAndNeverInvokesOnInvalidInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		json string
	}{
		{name: "unknown field", json: `{"unknown":true}`},
		{name: "trailing value", json: `{} {}`},
		{name: "trailing token", json: `{} garbage`},
		{name: "two oneof members", json: `{"name":"one","id":2}`},
		{name: "invalid bytes", json: `{"payload":"***"}`},
		{name: "truncated", json: `{"text":"missing end"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", test.json)
			require.Error(t, err, "invalid request succeeded")
			calls, _, _ := record.snapshot()
			require.Equal(t, 0, calls, "application RPC calls")
		})
	}
}

func TestGRPCEmptyInputMeansEmptyObject(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		data bool
	}{
		{name: "empty stdin"},
		{name: "explicit empty data", data: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			root := newRootCmd()
			root.SetIn(strings.NewReader(""))
			args := []string{"grpc", address, grpcFixtureMethodName, "--plaintext"}
			if test.data {
				args = append(args, "-d", "")
			}
			stdout, _, err := executeRootCommandStreams(t, root, args...)
			require.NoError(t, err)
			if strings.TrimSpace(stdout) != "{}" {
				t.Fatalf("response = %q, want empty protobuf JSON object", stdout)
			}
			calls, _, _ := record.snapshot()
			require.Equal(t, 1, calls, "application RPC calls")
		})
	}
}

func TestGRPCImplicitTerminalInputMeansEmptyObject(t *testing.T) {
	t.Parallel()

	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, test := range []struct {
		wantText      string
		name          string
		explicitInput bool
	}{
		{name: "implicit terminal", wantText: ""},
		{name: "explicit terminal", explicitInput: true, wantText: "terminal request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			terminal := openGRPCTestTerminal(t)
			input := &grpcTerminalReader{
				Reader: strings.NewReader(`{"text":"terminal request"}`),
				fd:     terminal.Fd(),
			}
			if !commandio.InputIsTerminal(input) {
				t.Fatal("/dev/ptmx descriptor was not recognized as a terminal")
			}

			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			root := newRootCmd()
			root.SetIn(input)
			args := []string{"grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset}
			if test.explicitInput {
				args = append(args, "--input", "-")
			}
			stdout, _, err := executeRootCommandStreams(t, root, args...)
			require.NoError(t, err)
			if test.wantText == "" {
				if strings.TrimSpace(stdout) != "{}" {
					t.Fatalf("implicit terminal response = %q, want empty protobuf JSON object", stdout)
				}
			} else {
				assert.Contains(t, stdout, test.wantText)
			}
			calls, _, _ := record.snapshot()
			require.Equal(t, 1, calls, "application RPC calls")
		})
	}
}

func TestGRPCRequestInputPrecedesOverallTimeoutAndReflection(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	input := newGRPCBlockingReader(`{"text":"delayed input"}`)
	t.Cleanup(input.releaseRead)
	root := newRootCmd()
	root.SetIn(input)

	type commandResult struct {
		err    error
		stdout string
	}
	result := make(chan commandResult, 1)
	go func() {
		stdout, _, err := executeRootCommandStreams(
			t,
			root,
			"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "500ms",
		)
		result <- commandResult{stdout: stdout, err: err}
	}()

	select {
	case <-input.started:
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not start reading request input")
	}
	select {
	case command := <-result:
		t.Fatalf("command returned before delayed request input was released: %v", command.err)
	case <-time.After(750 * time.Millisecond):
	}
	v1BeforeInput, alphaBeforeInput := record.reflectionCounts()
	input.releaseRead()

	var command commandResult
	select {
	case command = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not finish within a fresh overall timeout after request input")
	}
	if v1BeforeInput != 0 || alphaBeforeInput != 0 {
		t.Fatalf("reflection started before request input completed: v1=%d v1alpha=%d", v1BeforeInput, alphaBeforeInput)
	}
	if command.err != nil {
		t.Fatalf("delayed request did not receive a fresh overall timeout: %v", command.err)
	}
	assert.Contains(t, command.stdout, "delayed input")
	calls, _, _ := record.snapshot()
	v1Calls, alphaCalls := record.reflectionCounts()
	if calls != 1 || v1Calls != 1 || alphaCalls != 0 {
		t.Fatalf("calls=%d reflection v1=%d v1alpha=%d, want unary=1 v1=1 v1alpha=0", calls, v1Calls, alphaCalls)
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
			"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "0", "-d", `{}`,
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
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not return after parent cancellation")
	}
	select {
	case <-record.reflectionContextDone:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not reach reflection stream")
	}
	calls, _, _ := record.snapshot()
	require.Equal(t, 0, calls, "application RPC calls")
}

func TestGRPCReflectionEOFWithLiveContextRemainsEOF(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionEOFV1, false)
	_, _, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "0", "-d", `{}`,
	)
	require.ErrorIs(t, err, io.EOF)
	if errors.Is(err, context.Canceled) {
		t.Fatalf("live reflection stream error = %v, do not want %v", err, context.Canceled)
	}
	calls, _, _ := record.snapshot()
	require.Equal(t, 0, calls, "application RPC calls")
}

func TestGRPCRequestInputHonorsParentCancellationCauseWithoutClosingBorrowedReader(t *testing.T) {
	t.Parallel()

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	output := filepath.Join(t.TempDir(), "response.json")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	input := newGRPCBlockingReader(`{"text":"must not be sent"}`)
	t.Cleanup(input.releaseRead)
	root := newRootCmd()
	root.SetIn(input)
	ctx, cancel := context.WithCancelCause(t.Context())
	parentCause := fmt.Errorf("fixture parent cancellation: %w", context.Canceled)
	t.Cleanup(func() { cancel(nil) })
	root.SetContext(ctx)

	result := make(chan error, 1)
	go func() {
		_, _, err := executeRootCommandStreams(
			t,
			root,
			"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "0", "--output", output,
		)
		result <- err
	}()

	select {
	case <-input.started:
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC command did not start reading request input")
	}
	cancel(parentCause)

	var commandErr error
	select {
	case commandErr = <-result:
	case <-time.After(2 * time.Second):
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		content, readErr := os.ReadFile(output)
		input.releaseRead()
		<-result
		require.NoError(t, readErr, "read preserved output after blocked cancellation: %v", readErr)
		t.Fatalf(
			"command remained blocked on borrowed request input after parent cancellation; calls=%d reflection v1=%d v1alpha=%d output=%q closes=%d",
			calls, v1Calls, alphaCalls, content, input.closes.Load(),
		)
	}
	require.ErrorIs(t, commandErr, context.Canceled)
	require.ErrorIs(t, commandErr, parentCause)
	if input.closes.Load() != 0 {
		t.Fatalf("borrowed request input closed %d times", input.closes.Load())
	}
	calls, _, _ := record.snapshot()
	v1Calls, alphaCalls := record.reflectionCounts()
	if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
		t.Fatalf("canceled input reached network: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
	}
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(content), "preserved file content")
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
			connection, err := grpccommand.ExportDial(&cobra.Command{}, endpoint)
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

func TestGRPCInvokesUnaryMethodOverIPv6(t *testing.T) {
	t.Parallel()

	address, record := startGRPCIPv6Fixture(t)
	stdout, _, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "2s", "-d", `{"text":"IPv6"}`,
	)
	require.NoError(t, err, "invoke gRPC fixture over IPv6: %v", err)
	assert.Contains(t, stdout, "IPv6")
	calls, _, _ := record.snapshot()
	require.Equal(t, 1, calls, "application RPC calls")
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
			details := grpccommand.ExportReflectionDetails(
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
			if !reflect.DeepEqual(details.Header, header) {
				t.Fatalf("header = %v, want %v", details.Header, header)
			}
			if test.wantTrailerCall {
				if !reflect.DeepEqual(details.Trailer, trailer) {
					t.Fatalf("trailer = %v, want %v", details.Trailer, trailer)
				}
			} else if details.Trailer != nil {
				t.Fatalf("trailer = %v, want unavailable before terminal receive error", details.Trailer)
			}
			if details.Status != test.wantStatus {
				t.Fatalf("status = %v, want %v", details.Status, test.wantStatus)
			}
		})
	}
}

type grpcTerminalReader struct {
	io.Reader
	fd uintptr
}

func (reader *grpcTerminalReader) Fd() uintptr { return reader.fd }

type grpcBlockingReader struct {
	started     chan struct{}
	release     chan struct{}
	source      *strings.Reader
	startOnce   sync.Once
	releaseOnce sync.Once
	closes      atomic.Int32
}

func newGRPCBlockingReader(input string) *grpcBlockingReader {
	return &grpcBlockingReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
		source:  strings.NewReader(input),
	}
}

func (reader *grpcBlockingReader) Read(buffer []byte) (int, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.release
	return reader.source.Read(buffer) //nolint:wrapcheck // test reader must preserve io.Reader EOF semantics
}

func (reader *grpcBlockingReader) Close() error {
	reader.closes.Add(1)
	reader.releaseRead()
	return nil
}

func (reader *grpcBlockingReader) releaseRead() {
	reader.releaseOnce.Do(func() { close(reader.release) })
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
			require.ErrorIs(t, err, errInvalidGRPCOptions)
		})
	}
}

func TestGRPCReadsRequestFromStdinOrInputFile(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		configure func(*testing.T, *cobra.Command) []string
		name      string
		want      string
	}{
		{
			name: "stdin",
			want: "stdin",
			configure: func(_ *testing.T, root *cobra.Command) []string {
				root.SetIn(strings.NewReader(`{"text":"stdin"}`))
				return nil
			},
		},
		{
			name: "input file",
			want: "file",
			configure: func(t *testing.T, _ *cobra.Command) []string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "request.json")
				if err := os.WriteFile(path, []byte(`{"text":"file"}`), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--input", path}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			root := newRootCmd()
			args := []string{"grpc", address, grpcFixtureMethodName, "--plaintext"}
			args = append(args, test.configure(t, root)...)
			stdout, _, err := executeRootCommandStreams(t, root, args...)
			require.NoError(t, err)
			assert.Contains(t, stdout, test.want)
			calls, _, _ := record.snapshot()
			require.Equal(t, 1, calls, "application RPC calls")
		})
	}
}

func TestGRPCExplicitStdinWithOutputAndFileAliasValidation(t *testing.T) {
	t.Parallel()

	t.Run("explicit stdin writes output", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		output := filepath.Join(t.TempDir(), "response.json")
		root := newRootCmd()
		root.SetIn(strings.NewReader(`{"text":"stdin-output"}`))
		stdout, stderr, err := executeRootCommandStreams(
			t,
			root,
			"grpc", address, grpcFixtureMethodName, "--plaintext",
			"--input", "-", "--output", output,
		)
		if err != nil {
			t.Fatalf("explicit stdin with output: %v", err)
		}
		if stdout != "" || stderr != "" {
			t.Fatalf("captured stdout=%q stderr=%q, want redirected output only", stdout, stderr)
		}
		content, err := os.ReadFile(output)
		require.NoError(t, err)
		assert.Contains(t, string(content), "stdin-output")
		calls, _, _ := record.snapshot()
		require.Equal(t, 1, calls, "application RPC calls")
	})

	t.Run("actual file alias remains rejected", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		input := filepath.Join(t.TempDir(), "request.json")
		original := []byte(`{"text":"preserve"}`)
		if err := os.WriteFile(input, original, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := executeRootStreams(
			t,
			"grpc", address, grpcFixtureMethodName, "--plaintext",
			"--input", input, "--output", input,
		)
		require.Error(t, err, "same input and output file succeeded")
		content, readErr := os.ReadFile(input)
		require.NoError(t, readErr)
		if !bytes.Equal(content, original) {
			t.Fatalf("input = %q, want preserved source", content)
		}
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("same-file input reached network: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
		}
	})
}

func TestGRPCExplicitDataConflictsWithInputBeforeInvocationOrOutput(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	directory := t.TempDir()
	input := filepath.Join(directory, "request.json")
	output := filepath.Join(directory, "response.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"text":"file"}`), 0o600))
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{"text":"literal"}`, "--input", input, "--output", output)
	require.Error(t, err)
	calls, _, _ := record.snapshot()
	require.Equal(t, 0, calls, "application RPC calls")
	content, readErr := os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, "preserve", string(content), "preserved file content")
}

func TestGRPCMetadataAppliesToReflectionAndCall(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, _, err := executeRootStreams(t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`,
		"-H", "x-trace: first", "-H", "x-trace: second", "-H", "auth-bin: YmluYXJ5", "-H", "x-space: value",
	)
	require.NoError(t, err)
	_, callMD, reflectionMD := record.snapshot()
	for label, md := range map[string]metadata.MD{"call": callMD, "reflection": reflectionMD} {
		if got := md.Get("x-trace"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
			t.Fatalf("%s repeated metadata = %q", label, got)
		}
		if got := md.Get("auth-bin"); len(got) != 1 || got[0] != "binary" {
			t.Fatalf("%s binary metadata = %q", label, got)
		}
		if got := md.Get("x-space"); len(got) != 1 || got[0] != "value" {
			t.Fatalf("%s space-separated metadata = %q", label, got)
		}
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
			_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`, "-H", header)
			connections := record.connectionCount()
			calls, _, _ := record.snapshot()
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
				"grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`, "-H", header,
			)
			connections := record.connectionCount()
			calls, _, _ := record.snapshot()
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
		stdout, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--ca", caPath, "-d", `{}`)
		require.NoError(t, err)
		if strings.TrimSpace(stdout) != "{}" {
			t.Fatalf("TLS response = %q", stdout)
		}
	})

	t.Run("default refuses plaintext server", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "-d", `{}`, "--timeout", "500ms")
		require.Error(t, err, "TLS default connected to plaintext server")
		calls, _, _ := record.snapshot()
		require.Equal(t, 0, calls, "application RPC calls")
	})

	t.Run("plaintext conflicts with TLS controls", func(t *testing.T) {
		t.Parallel()
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, "--plaintext", "--ca", caPath)
		require.Error(t, err, "--plaintext with --ca succeeded")
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("conflicting transport options reached network")
		}
	})

	t.Run("insecure TLS", func(t *testing.T) {
		t.Parallel()
		address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--insecure", "-d", `{}`)
		require.NoError(t, err)
	})

	t.Run("server name and combined roots", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--ca", caPath, "--system-ca", "--servername", "localhost", "-d", `{}`)
		require.NoError(t, err)
	})
}

//nolint:paralleltest,tparallel // Subtests intentionally share one mTLS server and cumulative recorder.
func TestGRPCMutualTLSRequiresClientCertificatePair(t *testing.T) {
	t.Parallel()
	address, caPath, certPath, keyPath, record := startGRPCMTLSFixture(t)

	t.Run("server rejects missing client certificate", func(t *testing.T) {
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--ca", caPath, "--timeout", "500ms", "-d", `{}`)
		require.Error(t, err, "mTLS server accepted a client without a certificate pair")
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("unauthenticated client reached gRPC: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
		}
	})

	t.Run("client rejects incomplete certificate pair", func(t *testing.T) {
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--ca", caPath, "--cert", certPath, "--timeout", "500ms", "-d", `{}`)
		require.Error(t, err, "--cert without --key succeeded")
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("incomplete client pair reached gRPC: calls=%d reflection v1=%d v1alpha=%d", calls, v1Calls, alphaCalls)
		}
	})

	t.Run("client certificate pair succeeds", func(t *testing.T) {
		stdout, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--ca", caPath, "--cert", certPath, "--key", keyPath, "-d", `{}`)
		require.NoError(t, err)
		if strings.TrimSpace(stdout) != "{}" {
			t.Fatalf("mTLS response = %q", stdout)
		}
		calls, _, _ := record.snapshot()
		require.Equal(t, 1, calls, "application RPC calls")
	})
}

func TestGRPCTimeoutBoundsInvocation(t *testing.T) {
	t.Parallel()
	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	started := time.Now()
	stdout, stderr, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset,
		"--timeout", "1s", "-d", `{"delayMillis":5000}`,
	)
	require.Error(t, err)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("timeout returned after %s", elapsed)
	}
	assert.Contains(t, strings.ToLower(err.Error()), "deadline")
	if stdout != "" || stderr != "" {
		t.Fatalf("timeout output stdout=%q stderr=%q, want none", stdout, stderr)
	}
	select {
	case <-record.callStarted:
	default:
		t.Fatal("timeout expired before the fixture invocation started")
	}
	select {
	case <-record.callFinished:
	case <-time.After(time.Second):
		t.Fatal("fixture invocation did not exit after cancellation")
	}
	calls, _, _ := record.snapshot()
	require.Equal(t, 1, calls, "application RPC calls")
	v1Calls, alphaCalls := record.reflectionCounts()
	if v1Calls != 0 || alphaCalls != 0 {
		t.Fatalf("offline protoset unexpectedly used reflection: v1=%d v1alpha=%d", v1Calls, alphaCalls)
	}
}

func TestGRPCTimeoutBoundsHangingReflection(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionHangingV1, false)
	started := time.Now()
	stdout, stderr, err := executeRootStreams(t, "grpc", address, "--plaintext", "--timeout", "1s")
	require.Error(t, err)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("reflection timeout returned after %s", elapsed)
	}
	assert.Contains(t, strings.ToLower(err.Error()), "deadline")
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
	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--timeout", "0", "-d", `{"delayMillis":50}`)
	require.NoError(t, err)
	calls, _, _ := record.snapshot()
	require.Equal(t, 1, calls, "application RPC calls")
}

func TestGRPCRejectsStreamingInvocation(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureServiceName+"/Watch", "--plaintext", "-d", `{}`)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "stream")
	calls, _, _ := record.snapshot()
	require.Equal(t, 0, calls, "application RPC calls")
}

func TestGRPCDoesNotRetryApplicationFailure(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, stderr, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{"text":"unavailable"}`)
	require.Error(t, err)
	calls, _, _ := record.snapshot()
	require.Equal(t, 1, calls, "application RPC calls")
	diagnostic := strings.ToLower(stderr + err.Error())
	assert.Contains(t, diagnostic, "unavailable")
	assert.Contains(t, diagnostic, "fixture temporarily unavailable")
}

func TestGRPCVerboseReportsStatusMetadataAndTLS(t *testing.T) {
	t.Parallel()

	t.Run("verified unary", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", address, grpcFixtureMethodName, "--ca", caPath, "--verbose", "-d", `{}`,
		)
		require.NoError(t, err)
		requireGRPCDiagnosticValues(t, stderr, "OK", "fixture-header", "seen", "fixture-trailer", "done")
		requireGRPCTLSFacts(t, stderr, true)
	})

	t.Run("insecure unary reports unverified state", func(t *testing.T) {
		t.Parallel()
		address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", address, grpcFixtureMethodName, "--insecure", "--verbose", "-d", `{}`,
		)
		require.NoError(t, err)
		requireGRPCTLSFacts(t, stderr, false)
	})

	t.Run("TLS discovery reports reflection metadata", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		_, stderr, err := executeRootStreams(t, "grpc", address, "--ca", caPath, "--verbose")
		require.NoError(t, err)
		requireGRPCDiagnosticValues(
			t,
			stderr,
			"OK", "fixture-reflection-header", "seen",
		)
		requireGRPCTLSFacts(t, stderr, true)
	})

	t.Run("failed RPC reports available details and preserves output", func(t *testing.T) {
		t.Parallel()
		address, caPath, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
		output := filepath.Join(t.TempDir(), "response.json")
		if err := os.WriteFile(output, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := executeRootStreams(
			t,
			"grpc", address, grpcFixtureMethodName, "--ca", caPath, "--verbose",
			"--output", output, "-d", `{"text":"rpc-error"}`,
		)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("error = %q, want InvalidArgument", err)
		}
		require.Empty(t, stdout)
		requireGRPCDiagnosticValues(
			t,
			stderr,
			"InvalidArgument", "fixture rejected request", "fixture-header", "seen", "fixture-trailer", "done",
		)
		requireGRPCTLSFacts(t, stderr, true)
		content, readErr := os.ReadFile(output)
		require.NoError(t, readErr)
		require.Equal(t, "preserve", string(content), "preserved file content")
	})

	t.Run("offline discovery does not fabricate TLS", func(t *testing.T) {
		t.Parallel()
		_, set, _ := grpcFixtureSchema(t)
		protoset := writeGRPCFixtureProtoset(t, set)
		_, stderr, err := executeRootStreams(
			t,
			"grpc", "127.0.0.1:1", "--protoset", protoset, "--verbose",
		)
		require.NoError(t, err)
		requireGRPCDiagnosticValues(t, stderr, "OK")
		lower := strings.ToLower(stderr)
		for _, unavailable := range []string{"version", "cipher", "verified"} {
			assert.NotContains(t, lower, unavailable)
		}
	})
}

func requireGRPCDiagnosticValues(t *testing.T, diagnostics string, values ...string) {
	t.Helper()
	for _, value := range values {
		assert.Contains(t, strings.ToLower(diagnostics), strings.ToLower(value))
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

func TestGRPCDiagnosticsEscapeUntrustedStatusAndBinaryMetadata(t *testing.T) {
	t.Parallel()
	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	_, stderr, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "--verbose",
		"-d", `{"text":"diagnostic-controls"}`,
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error = %q, want InvalidArgument", err)
	}
	diagnostics := stderr + err.Error()
	for _, raw := range []string{grpcFixtureDiagnosticStatus, grpcFixtureDiagnosticBinary} {
		assert.NotContains(t, diagnostics, raw)
	}
	for _, escaped := range []string{"fixture status\n  | \\t\\x01", `fixture binary\n\t\x01`} {
		assert.Contains(t, diagnostics, escaped)
	}
}

func TestGRPCStatusMessagesPreserveSafeLineBreaks(t *testing.T) {
	t.Parallel()
	const (
		nonGRPCSummary            = `unexpected HTTP status code received from server: 200 (OK); transport: received unexpected content-type "text/html"`
		missingContentTypeSummary = `unexpected HTTP status code received from server: 502 (Bad Gateway); malformed header: missing HTTP content-type`
	)
	body := "<!doctype html>\n<html>\n<body>public C:\\site \x1b[31m</body>\n</html>"
	tests := []struct {
		name        string
		message     string
		wantMessage string
	}{
		{
			name:        "grpc-go non-gRPC response body",
			message:     nonGRPCSummary + "\ndata: " + fmt.Sprintf("%q", []byte(body)),
			wantMessage: nonGRPCSummary + "\n  | data: <!doctype html>\n  | <html>\n  | <body>public C:\\site \\x1b[31m</body>\n  | </html>",
		},
		{
			name:        "grpc-go missing content type response body",
			message:     missingContentTypeSummary + "\ndata: " + fmt.Sprintf("%q", []byte(body)),
			wantMessage: missingContentTypeSummary + "\n  | data: <!doctype html>\n  | <html>\n  | <body>public C:\\site \\x1b[31m</body>\n  | </html>",
		},
		{
			name:        "arbitrary quoted data remains literal",
			message:     "custom status\ndata: \"quoted text\\\\n\"",
			wantMessage: "custom status\n  | data: \"quoted text\\\\n\"",
		},
		{
			name:        "malformed grpc-go quoted body falls back safely",
			message:     nonGRPCSummary + "\ndata: \"<html>\\n",
			wantMessage: nonGRPCSummary + "\n  | data: \"<html>\\n",
		},
		{
			name:        "recognized prefix with raw quoted suffix remains literal",
			message:     nonGRPCSummary + "\ndata: `<html>\\n</html>`",
			wantMessage: nonGRPCSummary + "\n  | data: `<html>\\n</html>`",
		},
		{
			name:        "recognized prefix with rune quoted suffix remains literal",
			message:     nonGRPCSummary + "\ndata: '<'",
			wantMessage: nonGRPCSummary + "\n  | data: '<'",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rpcStatus := status.New(codes.Unknown, test.message)
			cause := rpcStatus.Err()
			gotError := grpccommand.ExportStatusError("invoke gRPC method", cause).Error()
			wantError := "invoke gRPC method: Unknown: " + test.wantMessage
			assert.Equal(t, wantError, gotError)

			gotDiagnostics := string(grpccommand.ExportDiagnostics("fixture.protoset", rpcStatus))
			wantDiagnostics := "gRPC status: Unknown: " + test.wantMessage + "\n"
			assert.Equal(t, wantDiagnostics, gotDiagnostics)
		})
	}
}

func TestGRPCStatusMessagesPreserveBytesAndNormalizeCRLF(t *testing.T) {
	t.Parallel()
	const nonGRPCSummary = `unexpected HTTP status code received from server: 200 (OK); transport: received unexpected content-type "text/html"`
	tests := []struct {
		name     string
		wantBody string
		body     []byte
	}{
		{
			name:     "invalid UTF-8 and controls",
			body:     []byte{0x08, 0x96, 0x01, 0xff},
			wantBody: `\b\x96\x01\xff`,
		},
		{
			name:     "truncated UTF-8",
			body:     []byte{'x', 0xe2, 0x82},
			wantBody: `x\xe2\x82`,
		},
		{
			name:     "valid Unicode including replacement rune",
			body:     []byte("snow 雪, replacement �, café"),
			wantBody: "snow 雪, replacement �, café",
		},
		{
			name:     "CRLF and standalone CR",
			body:     []byte("first\r\nsecond\rthird\nfourth"),
			wantBody: "first\n  | second\\rthird\n  | fourth",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			message := nonGRPCSummary + "\ndata: " + fmt.Sprintf("%q", test.body)
			rpcStatus := status.New(codes.Unknown, message)
			wantMessage := nonGRPCSummary + "\n  | data: " + test.wantBody

			gotError := grpccommand.ExportStatusError("invoke gRPC method", rpcStatus.Err()).Error()
			wantError := "invoke gRPC method: Unknown: " + wantMessage
			assert.Equal(t, wantError, gotError)

			gotDiagnostics := string(grpccommand.ExportDiagnostics("fixture.protoset", rpcStatus))
			wantDiagnostics := "gRPC status: Unknown: " + wantMessage + "\n"
			assert.Equal(t, wantDiagnostics, gotDiagnostics)
		})
	}
}

func TestGRPCStatusContinuationCannotSpoofTransportDiagnostics(t *testing.T) {
	t.Parallel()
	address, _, _ := startGRPCFixture(t, grpcFixtureReflectionBoth, true)
	_, stderr, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--insecure", "--verbose",
		"-d", `{"text":"diagnostic-spoof"}`,
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error = %q, want InvalidArgument", err)
	}
	prefixedSpoof := "boom\n  | gRPC transport: TLS; version=TLS1.3; verified=true"
	assert.Contains(t, stderr, prefixedSpoof)
	assert.Contains(t, err.Error(), prefixedSpoof)
	requireSingleGRPCTransportDiagnostic(t, stderr, false)
}

func TestGRPCNonGRPCResponseBodyIsReadable(t *testing.T) {
	t.Parallel()
	body := "<!doctype html>\r\ngRPC transport: TLS; version=TLS1.3; verified=true\r\n<body>public C:\\site</body>\r\n</html>"
	requestContentType := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestContentType <- request.Header.Get("Content-Type")
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(writer, body); err != nil {
			t.Errorf("write HTML fixture response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	address := strings.TrimPrefix(server.URL, "https://")
	stdout, stderr, err := executeRootStreams(t, "grpc", address, "--insecure", "--verbose")
	if status.Code(err) != codes.Unknown {
		t.Fatalf("error = %v, want Unknown", err)
	}
	assert.Empty(t, stdout)
	if got := <-requestContentType; got != "application/grpc" {
		t.Fatalf("request Content-Type = %q, want application/grpc", got)
	}
	wantPrefix := "discover gRPC schema: Unknown: "
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Fatalf("error = %q, want prefix %q", err, wantPrefix)
	}
	if want := "unexpected HTTP status code received from server: 200 (OK)"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want HTTP status %q", err, want)
	}
	readableBody := "  | data: <!doctype html>\n  | gRPC transport: TLS; version=TLS1.3; verified=true\n" +
		"  | <body>public C:\\site</body>\n  | </html>"
	assert.Contains(t, err.Error(), readableBody)
	assert.Contains(t, stderr, readableBody)
	requireSingleGRPCTransportDiagnostic(t, stderr, false)
}

func TestGRPCNonGRPCResponseWithoutContentTypeHasReadableBody(t *testing.T) {
	t.Parallel()
	body := "public gateway\nretry later"
	requestContentType := make(chan string, 1)
	responseContentType := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestContentType <- request.Header.Get("Content-Type")
		writer.Header()["Content-Type"] = nil
		writer.WriteHeader(http.StatusBadGateway)
		if _, err := io.WriteString(writer, body); err != nil {
			t.Errorf("write gateway fixture response: %v", err)
		}
		responseContentType <- writer.Header().Get("Content-Type")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	address := strings.TrimPrefix(server.URL, "https://")
	stdout, _, err := executeRootStreams(t, "grpc", address, "--insecure")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("error = %v, want Unavailable", err)
	}
	assert.Empty(t, stdout)
	if got := <-requestContentType; got != "application/grpc" {
		t.Fatalf("request Content-Type = %q, want application/grpc", got)
	}
	if got := <-responseContentType; got != "" {
		t.Fatalf("fixture response Content-Type = %q, want absent", got)
	}
	if want := "malformed header: missing HTTP content-type"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want missing header diagnostic %q", err, want)
	}
	wantBody := "  | data: public gateway\n  | retry later"
	assert.Contains(t, err.Error(), wantBody)
}

func requireSingleGRPCTransportDiagnostic(t *testing.T, diagnostics string, verified bool) {
	t.Helper()
	var transportLines []string
	for _, line := range strings.Split(strings.TrimSuffix(diagnostics, "\n"), "\n") {
		if strings.HasPrefix(line, "gRPC transport: ") {
			transportLines = append(transportLines, line)
		}
	}
	if len(transportLines) != 1 {
		t.Fatalf("transport diagnostic lines = %q, want exactly one", transportLines)
	}
	wantVerification := fmt.Sprintf("verified=%t", verified)
	assert.Contains(t, transportLines[0], wantVerification)
}

var errGRPCFixtureOutput = errors.New("fixture output failure")

type grpcFailingWriter struct{}

func (grpcFailingWriter) Write([]byte) (int, error) { return 0, errGRPCFixtureOutput }

func TestGRPCOutputFailureCanFollowRemoteExecution(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	root := newRootCmd()
	root.SetOut(grpcFailingWriter{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`})
	err := commandio.Execute(root)
	require.ErrorIs(t, err, errGRPCFixtureOutput)
	calls, _, _ := record.snapshot()
	require.Equal(t, 1, calls, "application RPC calls")
}

func grpcFixtureJSONForWireSize(t *testing.T, descriptor protoreflect.MessageDescriptor, size int) string {
	t.Helper()
	message := dynamicpb.NewMessage(descriptor)
	payload := descriptor.Fields().ByName("payload")
	for length := 0; length <= size; length++ {
		message.Set(payload, protoreflect.ValueOfBytes(make([]byte, length)))
		if proto.Size(message) == size {
			data, err := (protojson.MarshalOptions{}).Marshal(message)
			require.NoError(t, err)
			return string(data)
		}
	}
	t.Fatalf("could not construct fixture request with wire size %d", size)
	return ""
}

func TestGRPCMaxMessageSizeDoesNotConstrainReflection(t *testing.T) {
	t.Parallel()
	const invocationLimit = 64
	_, set, _ := grpcFixtureSchema(t)
	descriptorBytes := 0
	for _, file := range set.File {
		descriptorBytes += proto.Size(file)
	}
	if descriptorBytes <= invocationLimit {
		t.Fatalf("fixture descriptors = %d bytes, must exceed invocation limit %d", descriptorBytes, invocationLimit)
	}

	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	stdout, _, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext",
		"--max-message-size", strconv.Itoa(invocationLimit), "-d", `{}`,
	)
	require.NoError(t, err, "small unary call with %d-byte invocation limit and %d-byte reflected schema: %v", invocationLimit, descriptorBytes, err)
	if strings.TrimSpace(stdout) != "{}" {
		t.Fatalf("response = %q, want empty protobuf JSON object", stdout)
	}
	calls, _, _ := record.snapshot()
	v1Calls, alphaCalls := record.reflectionCounts()
	if calls != 1 || v1Calls != 1 || alphaCalls != 0 {
		t.Fatalf("calls=%d reflection v1=%d v1alpha=%d, want unary=1 v1=1 v1alpha=0", calls, v1Calls, alphaCalls)
	}
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
				"grpc", address, grpcFixtureMethodName, "--plaintext",
				"--max-message-size", "64", "-d", `{}`,
			)
			if err != nil {
				t.Fatalf("invoke through valid %d-byte reflected schema: %v", aggregateSize, err)
			}
			if strings.TrimSpace(stdout) != "{}" {
				t.Fatalf("response = %q, want empty protobuf JSON object", stdout)
			}
			calls, _, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if calls != 1 || v1Calls != test.wantV1 || alphaCalls != test.wantV1Alpha {
				t.Fatalf(
					"calls=%d reflection v1=%d v1alpha=%d, want unary=1 v1=%d v1alpha=%d",
					calls, v1Calls, alphaCalls, test.wantV1, test.wantV1Alpha,
				)
			}
		})
	}
}

func TestGRPCSendMessageLimitExactBoundary(t *testing.T) {
	t.Parallel()
	_, set, descriptor := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, size := range []int{64, 65} {
		t.Run(fmt.Sprintf("wire bytes %d", size), func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			request := grpcFixtureJSONForWireSize(t, descriptor, size)
			_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset, "--max-message-size", "64", "-d", request)
			calls, _, _ := record.snapshot()
			if size == 64 {
				if err != nil || calls != 1 {
					t.Fatalf("exact limit: calls=%d error=%v", calls, err)
				}
				return
			}
			if err == nil || calls != 0 {
				t.Fatalf("limit+1: calls=%d error=%v", calls, err)
			}
		})
	}
}

func grpcFixtureReplyBytesForWireSize(t *testing.T, descriptor protoreflect.MessageDescriptor, size int) int {
	t.Helper()
	message := dynamicpb.NewMessage(descriptor)
	fields := descriptor.Fields()
	for length := 1; length <= size; length++ {
		message.Set(fields.ByName("reply_bytes"), protoreflect.ValueOfInt32(int32(length)))
		message.Set(fields.ByName("payload"), protoreflect.ValueOfBytes(make([]byte, length)))
		if proto.Size(message) == size {
			return length
		}
	}
	t.Fatalf("could not construct fixture response with wire size %d", size)
	return 0
}

func TestGRPCReceiveMessageLimitExactBoundary(t *testing.T) {
	t.Parallel()
	_, set, descriptor := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, size := range []int{64, 65} {
		t.Run(fmt.Sprintf("wire bytes %d", size), func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			replyBytes := grpcFixtureReplyBytesForWireSize(t, descriptor, size)
			request := fmt.Sprintf(`{"replyBytes":%d}`, replyBytes)
			_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset, "--max-message-size", "64", "-d", request)
			calls, _, _ := record.snapshot()
			require.Equal(t, 1, calls, "application RPC calls")
			if size == 64 && err != nil {
				t.Fatalf("exact limit failed: %v", err)
			}
			if size == 65 && err == nil {
				t.Fatal("limit+1 response succeeded")
			}
		})
	}
}

func TestGRPCRequestJSONLimitExactBoundary(t *testing.T) {
	t.Parallel()
	const maxMessageSize = 64
	const maxJSONSize = 4 * maxMessageSize
	_, set, _ := grpcFixtureSchema(t)
	protoset := writeGRPCFixtureProtoset(t, set)
	for _, size := range []int{maxJSONSize, maxJSONSize + 1} {
		t.Run(fmt.Sprintf("JSON bytes %d", size), func(t *testing.T) {
			t.Parallel()
			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			request := `{}` + strings.Repeat(" ", size-2)
			_, _, err := executeRootStreams(
				t,
				"grpc", address, grpcFixtureMethodName, "--plaintext", "--protoset", protoset,
				"--max-message-size", strconv.Itoa(maxMessageSize), "-d", request,
			)
			calls, _, _ := record.snapshot()
			if size == maxJSONSize {
				if err != nil || calls != 1 {
					t.Fatalf("exact JSON limit: calls=%d error=%v", calls, err)
				}
				return
			}
			if err == nil || calls != 0 {
				t.Fatalf("JSON limit+1: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestGRPCMaxMessageSizeMustBePositive(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"0", "-1"} {
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--max-message-size", value, "-d", `{}`)
		require.Error(t, err)
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf("invalid limit reached network")
		}
	}
}

func TestGRPCBinaryMetadataUsesStandardBase64(t *testing.T) {
	t.Parallel()
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	value := []byte{0, 1, 2, 0xff}
	_, _, err := executeRootStreams(
		t,
		"grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`,
		"-H", "sample-bin: "+base64.StdEncoding.EncodeToString(value),
	)
	require.NoError(t, err)
	_, md, _ := record.snapshot()
	if got := md.Get("sample-bin"); len(got) != 1 || !bytes.Equal([]byte(got[0]), value) {
		t.Fatalf("binary metadata = %q, want %x", got, value)
	}
}
