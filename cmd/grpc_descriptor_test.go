package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGRPCProtosetResolvesImportsAndDoesNotConnectForDiscovery(t *testing.T) {
	t.Parallel()
	_, set, _ := grpcFixtureSchema(t)
	path := writeGRPCFixtureProtoset(t, set)
	stdout, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path, "--describe", "fixture.v1.EchoRequest")
	if err != nil {
		t.Fatalf("offline imported descriptor discovery: %v", err)
	}
	for _, want := range []string{"EchoRequest", "Any", "labels"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("descriptor output %q does not contain %q", stdout, want)
		}
	}
}

func TestGRPCProtosetOutputAliasPreservesSourceWithoutNetwork(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		outputPath func(*testing.T, string) string
		name       string
	}{
		{
			name: "same path",
			outputPath: func(_ *testing.T, protoset string) string {
				return protoset
			},
		},
		{
			name: "hard link",
			outputPath: func(t *testing.T, protoset string) string {
				t.Helper()
				output := filepath.Join(filepath.Dir(protoset), "hardlink-output")
				if err := os.Link(protoset, output); err != nil {
					t.Skipf("create hard link: %v", err)
				}
				return output
			},
		},
		{
			name: "symbolic link",
			outputPath: func(t *testing.T, protoset string) string {
				t.Helper()
				output := filepath.Join(filepath.Dir(protoset), "symlink-output")
				if err := os.Symlink(protoset, output); err != nil {
					t.Skipf("create symbolic link: %v", err)
				}
				return output
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
			_, set, _ := grpcFixtureSchema(t)
			protoset := writeGRPCFixtureProtoset(t, set)
			before, err := os.ReadFile(protoset)
			if err != nil {
				t.Fatal(err)
			}
			output := test.outputPath(t, protoset)

			_, _, commandErr := executeRootStreams(
				t,
				"grpc", address, "--protoset", protoset, "--output", output,
			)
			after, readErr := os.ReadFile(protoset)
			if readErr != nil {
				t.Fatal(readErr)
			}
			calls, _ := record.snapshot()
			v1Calls, alphaCalls := record.reflectionCounts()
			if !errors.Is(commandErr, errSameInputOutput) || !bytes.Equal(after, before) ||
				calls != 0 || v1Calls != 0 || alphaCalls != 0 {

				t.Fatalf(
					"error=%v source bytes=%d want=%d calls=%d reflection v1=%d v1alpha=%d",
					commandErr, len(after), len(before), calls, v1Calls, alphaCalls,
				)
			}
		})
	}
}

func TestGRPCProtosetRejectsConflictingSymbols(t *testing.T) {
	t.Parallel()
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		minimalGRPCFixtureFile("one.proto", "conflict.v1", "Duplicate"),
		minimalGRPCFixtureFile("two.proto", "conflict.v1", "Duplicate"),
	}}
	path := writeGRPCFixtureProtoset(t, set)
	_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path)
	if err == nil {
		t.Fatal("protoset with duplicate full symbol succeeded")
	}
}

func TestGRPCDescriptorFileCountLimitExactBoundary(t *testing.T) {
	t.Parallel()
	for _, count := range []int{1024, 1025} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			t.Parallel()
			set := &descriptorpb.FileDescriptorSet{File: make([]*descriptorpb.FileDescriptorProto, count)}
			for index := range set.File {
				set.File[index] = minimalGRPCFixtureFile(fmt.Sprintf("many/%04d.proto", index), fmt.Sprintf("many.p%04d", index), "Message")
			}
			path := writeGRPCFixtureProtoset(t, set)
			_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path)
			if count == 1024 && err != nil {
				t.Fatalf("1024 descriptor files: %v", err)
			}
			if count == 1025 && err == nil {
				t.Fatal("1025 descriptor files succeeded")
			}
		})
	}
}

func TestGRPCDescriptorAggregateByteLimitExactBoundary(t *testing.T) {
	t.Parallel()
	for _, size := range []int{16 << 20, 16<<20 + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			file := grpcFixtureFileWithSerializedSize(t, size)
			if got := proto.Size(file); got != size {
				t.Fatalf("fixture descriptor size = %d, want %d", got, size)
			}
			set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}}
			if _, err := protodesc.NewFiles(set); err != nil {
				t.Fatalf("exact-size descriptor fixture is invalid: %v", err)
			}
			path := writeGRPCFixtureProtoset(t, set)
			_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path)
			if size == 16<<20 && err != nil {
				t.Fatalf("exact descriptor byte limit: %v", err)
			}
			if size == 16<<20+1 && err == nil {
				t.Fatal("descriptor byte limit+1 succeeded")
			}
		})
	}
}

func TestGRPCDescriptorNestingLimitCountsTopLevelAsOne(t *testing.T) {
	t.Parallel()
	for _, children := range []int{99, 100} {
		depth := children + 1
		t.Run(fmt.Sprintf("depth %d", depth), func(t *testing.T) {
			t.Parallel()
			root := &descriptorpb.DescriptorProto{Name: proto.String("Root")}
			parent := root
			for index := 1; index <= children; index++ {
				child := &descriptorpb.DescriptorProto{Name: proto.String(fmt.Sprintf("Child%d", index))}
				parent.NestedType = []*descriptorpb.DescriptorProto{child}
				parent = child
			}
			file := minimalGRPCFixtureFile("nested.proto", "nested.v1", "unused")
			file.MessageType = []*descriptorpb.DescriptorProto{root}
			path := writeGRPCFixtureProtoset(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
			_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path, "--describe", "nested.v1.Root")
			if depth == 100 && err != nil {
				t.Fatalf("depth 100 (top-level + 99 children): %v", err)
			}
			if depth == 101 && err == nil {
				t.Fatal("depth 101 (top-level + 100 children) succeeded")
			}
		})
	}
}

func TestGRPCRecursiveMessageDescriptorResolves(t *testing.T) {
	t.Parallel()
	file := minimalGRPCFixtureFile("recursive.proto", "recursive.v1", "Node")
	file.MessageType[0].Field = []*descriptorpb.FieldDescriptorProto{{
		Name:     proto.String("next"),
		JsonName: proto.String("next"),
		Number:   proto.Int32(1),
		Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
		TypeName: proto.String(".recursive.v1.Node"),
	}}
	path := writeGRPCFixtureProtoset(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	stdout, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", path, "--describe", "recursive.v1.Node")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Node") || !strings.Contains(stdout, "next") {
		t.Fatalf("recursive descriptor output = %q", stdout)
	}
}

func TestGRPCMalformedProtosetPreservesOutput(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	protoset := filepath.Join(directory, "bad.protoset")
	output := filepath.Join(directory, "output")
	if err := os.WriteFile(protoset, []byte{0x0a, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := executeRootStreams(t, "grpc", "127.0.0.1:1", "--protoset", protoset, "--output", output)
	if err == nil {
		t.Fatal("malformed protoset succeeded")
	}
	content, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "preserve" {
		t.Fatalf("output = %q, want preserved content", content)
	}
}

func minimalGRPCFixtureFile(name, packageName, messageName string) *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:        proto.String(name),
		Package:     proto.String(packageName),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String(messageName)}},
	}
}

func grpcFixtureFileWithSerializedSize(t *testing.T, size int) *descriptorpb.FileDescriptorProto {
	t.Helper()
	file := minimalGRPCFixtureFile("large.proto", "large.v1", "Message")
	grpcFixturePadFileToSerializedSize(t, file, size)
	return file
}

func grpcFixturePadFileToSerializedSize(t *testing.T, file *descriptorpb.FileDescriptorProto, size int) {
	t.Helper()
	location := &descriptorpb.SourceCodeInfo_Location{Path: []int32{4, 0}, Span: []int32{0, 0, 0}}
	file.SourceCodeInfo = &descriptorpb.SourceCodeInfo{Location: []*descriptorpb.SourceCodeInfo_Location{location}}
	comments := max(0, size-proto.Size(file)-8)
	for {
		location.LeadingComments = proto.String(strings.Repeat("x", comments))
		actual := proto.Size(file)
		if actual == size {
			return
		}
		comments += size - actual
		if comments < 0 {
			t.Fatalf("cannot construct descriptor of size %d", size)
		}
	}
}
