package cmd

import (
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const maxGRPCFuzzInput = 4 << 10

const grpcFuzzNetworkDelay = 25 * time.Millisecond

var errGRPCFuzzDescriptorLimits = errors.New("descriptor limits exceeded")

func FuzzGRPCProtobufJSONRequest(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"text":"hello","payload":"AAEC","count":"9223372036854775807","mode":"MODE_ACTIVE"}`,
		`{"name":"one","id":2}`,
		`{"unknown":true}`,
		`{} {}`,
		`{"text":`,
		`{"text":"rpc-error"}`,
		`{"text":"diagnostic-controls"}`,
		`{"text":"unavailable"}`,
		`{"replyBytes":2147483647,"delayMillis":2147483647}`,
		`{"extra":{"@type":"type.googleapis.com/fixture.v1.EchoRequest","text":"nested"}}`,
		`{"extra":{"@type":"type.googleapis.com/fixture.v1.Missing","text":"nested"}}`,
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxGRPCFuzzInput {
			t.Skip()
		}
		files, _, descriptor := grpcFixtureSchema(t)
		oracleInput := input
		if oracleInput == "" {
			oracleInput = `{}`
		}
		message := dynamicpb.NewMessage(descriptor)
		oracleErr := (protojson.UnmarshalOptions{
			Resolver:       dynamicpb.NewTypes(files),
			DiscardUnknown: false,
		}).Unmarshal([]byte(oracleInput), message)
		time.Sleep(grpcFuzzNetworkDelay)
		address, record := startGRPCPlainEchoFixture(t)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "--max-message-size", "4096", "-d", input)
		calls, _, _ := record.snapshot()
		if oracleErr == nil {
			if err != nil || calls != 1 {
				t.Fatalf("valid protobuf JSON rejected: error=%v calls=%d input=%q", err, calls, input)
			}
			return
		}
		if err == nil || calls != 0 {
			t.Fatalf("invalid protobuf JSON accepted: oracle=%v calls=%d input=%q", oracleErr, calls, input)
		}
	})
}

func FuzzGRPCMetadata(f *testing.F) {
	for _, seed := range []string{
		"x-test: value",
		"x-test-bin: YmluYXJ5",
		"x-repeat: first",
		"Bad_Key: value",
		"grpc-timeout: 1S",
		"connection: close",
		"keep-alive: timeout=5",
		"proxy-connection: close",
		"transfer-encoding: chunked",
		"upgrade: websocket",
		"host: example.test",
		"x-test: line\nbreak",
		"x-test-bin: ***",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		if len(header) > maxGRPCFuzzInput {
			t.Skip()
		}
		time.Sleep(grpcFuzzNetworkDelay)
		valid := referenceGRPCMetadata(header)
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, _, err := executeRootStreams(t, "grpc", address, grpcFixtureMethodName, "--plaintext", "-d", `{}`, "-H", header)
		connections := record.connectionCount()
		calls, _, _ := record.snapshot()
		v1Calls, alphaCalls := record.reflectionCounts()
		if valid {
			if err != nil || calls != 1 || v1Calls+alphaCalls == 0 {
				t.Fatalf("valid metadata rejected: error=%v calls=%d reflection v1=%d v1alpha=%d header=%q", err, calls, v1Calls, alphaCalls, header)
			}
			return
		}
		if err == nil || connections != 0 || calls != 0 || v1Calls != 0 || alphaCalls != 0 {
			t.Fatalf(
				"invalid metadata reached network: error=%v connections=%d calls=%d reflection v1=%d v1alpha=%d header=%q",
				err, connections, calls, v1Calls, alphaCalls, header,
			)
		}
	})
}

func referenceGRPCMetadata(header string) bool {
	key, value, found := strings.Cut(header, ":")
	if !found || key == "" || key != strings.ToLower(key) {
		return false
	}
	for _, character := range key {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	if strings.HasPrefix(key, "grpc-") {
		return false
	}
	switch key {
	case "connection", "content-type", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "upgrade", "user-agent":
		return false
	}
	value = strings.Trim(value, " ")
	for _, character := range value {
		if character < ' ' || character > '~' {
			return false
		}
	}
	if strings.HasSuffix(key, "-bin") {
		_, err := base64.StdEncoding.DecodeString(value)
		return err == nil
	}
	return true
}

func FuzzGRPCEndpoint(f *testing.F) {
	set := grpcFixtureSchemaForFuzz(f)
	protoset := writeGRPCFixtureProtosetForFuzz(f, set)
	for _, seed := range []string{
		"localhost:443",
		"127.0.0.1:1",
		"[::1]:8443",
		"missing-port",
		":443",
		"localhost:0",
		"localhost:65536",
		"[::1",
		"\x03:4",
		"local\u00a0host:443",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		if len(endpoint) > 1<<10 {
			t.Skip()
		}
		valid := referenceGRPCEndpoint(endpoint)
		_, _, err := executeRootStreams(t, "grpc", endpoint, "--protoset", protoset)
		if valid && err != nil {
			t.Fatalf("valid endpoint rejected: %v; endpoint %q", err, endpoint)
		}
		if !valid && err == nil {
			t.Fatalf("invalid endpoint accepted: %q", endpoint)
		}
	})
}

func referenceGRPCEndpoint(endpoint string) bool {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return false
	}
	for _, character := range host {
		if character <= ' ' || character == 127 || unicode.IsSpace(character) {
			return false
		}
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}

func FuzzGRPCMethodSelector(f *testing.F) {
	for _, seed := range []string{
		grpcFixtureMethodName,
		grpcFixtureServiceName + "/Watch",
		"fixture.v1.EchoService",
		"/Echo",
		"fixture.v1.EchoService/",
		"fixture.v1.EchoService/Echo/extra",
		"bad\nservice/Echo",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, selector string) {
		if len(selector) > 1<<10 {
			t.Skip()
		}
		time.Sleep(grpcFuzzNetworkDelay)
		address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
		_, _, err := executeRootStreams(t, "grpc", address, selector, "--plaintext", "-d", `{}`)
		calls, _, _ := record.snapshot()
		if selector == grpcFixtureMethodName {
			if err != nil || calls != 1 {
				t.Fatalf("valid unary selector rejected: error=%v calls=%d", err, calls)
			}
			return
		}
		if err == nil || calls != 0 {
			t.Fatalf("unsupported selector accepted: %q calls=%d", selector, calls)
		}
	})
}

func FuzzGRPCProtosetTruncation(f *testing.F) {
	set := grpcFixtureSchemaForFuzz(f)
	valid, err := proto.Marshal(set)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	for _, cut := range []int{0, 1, len(valid) / 2, len(valid) - 1} {
		f.Add(append([]byte(nil), valid[:cut]...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		decodedSet := &descriptorpb.FileDescriptorSet{}
		oracleErr := proto.Unmarshal(data, decodedSet)
		if oracleErr == nil && !grpcFuzzDescriptorSetWithinLimits(decodedSet) {
			oracleErr = errGRPCFuzzDescriptorLimits
		}
		if oracleErr == nil {
			_, oracleErr = protodesc.NewFiles(decodedSet)
		}
		path := filepath.Join(t.TempDir(), "fuzz.protoset")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, commandErr := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path)
		if oracleErr == nil && commandErr != nil {
			t.Fatalf("valid bounded protoset rejected: %v", commandErr)
		}
		if oracleErr != nil && commandErr == nil {
			t.Fatalf("invalid protoset accepted: oracle=%v", oracleErr)
		}
	})
}

func grpcFuzzDescriptorSetWithinLimits(set *descriptorpb.FileDescriptorSet) bool {
	if len(set.File) > 1024 {
		return false
	}
	type messageDepth struct {
		message *descriptorpb.DescriptorProto
		depth   int
	}
	for _, file := range set.File {
		stack := make([]messageDepth, 0, len(file.GetMessageType()))
		for _, message := range file.GetMessageType() {
			stack = append(stack, messageDepth{message: message, depth: 1})
		}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current.depth > 100 {
				return false
			}
			for _, nested := range current.message.GetNestedType() {
				stack = append(stack, messageDepth{message: nested, depth: current.depth + 1})
			}
		}
	}
	return true
}

func grpcFixtureSchemaForFuzz(f *testing.F) *descriptorpb.FileDescriptorSet {
	f.Helper()
	// Build through a tiny testing adapter so fuzz setup uses the same fixed
	// schema as the local server oracle without duplicating descriptors.
	file := minimalGRPCFixtureFile("fuzz.proto", "fuzz.v1", "Message")
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}}
	return set
}

func writeGRPCFixtureProtosetForFuzz(f *testing.F, set *descriptorpb.FileDescriptorSet) string {
	f.Helper()
	data, err := proto.Marshal(set)
	if err != nil {
		f.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "npc-grpc-fuzz-")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			f.Errorf("remove fuzz fixture directory: %v", err)
		}
	})
	path := filepath.Join(directory, "fixture.protoset")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		f.Fatal(err)
	}
	return path
}
