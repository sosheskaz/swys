package protoschema_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/sosheskaz/swys/internal/protoschema"
)

// maxFuzzProtosetWireSize bounds generated wire input well under MaxWireBytes
// so the read-size arm of Read stays a unit-test concern; file-count and
// nesting-depth limits are cheap to reach on the wire and are the arms this
// target generates. The aggregate 16 MiB descriptor budget likewise needs
// multi-megabyte inputs and is covered by unit tests.
const maxFuzzProtosetWireSize = 1 << 15

// FuzzReadDescriptorSetLimits drives descriptor-set wire bytes — user-supplied
// --protoset files and descriptors reflected from remote servers — through
// Read and New. Acceptance is re-derived from an independent unmarshal: sets
// that parse and stay inside the file-count and nesting limits must come back
// equal and resolve through protodesc exactly as a direct resolution does,
// while sets past either limit must fail with ErrLimit before resolution.
func FuzzReadDescriptorSetLimits(f *testing.F) {
	valid := fuzzProtosetDescriptorSet()
	wire := fuzzMarshalProtoset(f, valid)
	f.Add(wire)
	f.Add([]byte{})
	f.Add([]byte{0x0a})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add(wire[:1])
	f.Add(wire[:len(wire)/2])
	f.Add(wire[:len(wire)-1])
	f.Add(fuzzMarshalProtoset(f, fuzzFileCountSet(protoschema.MaxFiles)))
	f.Add(fuzzMarshalProtoset(f, fuzzFileCountSet(protoschema.MaxFiles+1)))
	f.Add(fuzzMarshalProtoset(f, fuzzNestingSet(protoschema.MaxDepth)))
	f.Add(fuzzMarshalProtoset(f, fuzzNestingSet(protoschema.MaxDepth+1)))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxFuzzProtosetWireSize {
			t.Skip()
		}

		expected := &descriptorpb.FileDescriptorSet{}
		if err := proto.Unmarshal(bytes.Clone(input), expected); err != nil {
			set, readErr := protoschema.Read(bytes.NewReader(input))
			if readErr == nil {
				t.Fatal("unparseable wire input accepted")
			}
			if set != nil {
				t.Fatalf("unparseable wire input returned %v files, want none", len(set.GetFile()))
			}
			if errors.Is(readErr, protoschema.ErrLimit) {
				t.Fatalf("unparseable wire input reported %v", readErr)
			}
			return
		}

		overFiles := len(expected.GetFile()) > protoschema.MaxFiles
		overDepth := fuzzProtosetNestingDepth(expected) > protoschema.MaxDepth
		set, readErr := protoschema.Read(bytes.NewReader(input))
		if overFiles || overDepth {
			if !errors.Is(readErr, protoschema.ErrLimit) {
				t.Fatalf("wire input past limits = %v, want ErrLimit", readErr)
			}
			if set != nil {
				t.Fatalf("wire input past limits returned %v files, want none", len(set.GetFile()))
			}
			return
		}
		if readErr != nil {
			t.Fatalf("wire input inside limits = %v, want success", readErr)
		}
		if !proto.Equal(set, expected) {
			t.Fatal("Read returned a different descriptor set than an independent unmarshal")
		}

		// Resolution must agree with a direct protodesc resolution of the
		// same set, and accepted schemas must be deterministic.
		_, directErr := protodesc.NewFiles(expected)
		schema, schemaErr := protoschema.New(set)
		if directErr != nil {
			if schemaErr == nil {
				t.Fatalf("set resolved by protoschema.New but not by protodesc: %v", directErr)
			}
			return
		}
		// A set protodesc resolves can still carry a malformed well-known
		// message, which New rejects with ErrSymbol in validateKnownMessages.
		if schemaErr != nil && !errors.Is(schemaErr, protoschema.ErrSymbol) {
			t.Fatalf("resolvable set failed in New: %v", schemaErr)
		}
		if schemaErr != nil {
			return
		}
		if !sort.StringsAreSorted(schema.Services) {
			t.Fatalf("services are not sorted: %v", schema.Services)
		}
		repeat, err := protoschema.New(set)
		if err != nil {
			t.Fatalf("New is not deterministic: %v", err)
		}
		if !reflect.DeepEqual(schema.Services, repeat.Services) {
			t.Fatalf("New is not deterministic: services %q then %q", schema.Services, repeat.Services)
		}
		if schema.Files.NumFiles() != repeat.Files.NumFiles() {
			t.Fatalf("New is not deterministic: %d files then %d", schema.Files.NumFiles(), repeat.Files.NumFiles())
		}
	})
}

func fuzzMarshalProtoset(f *testing.F, set *descriptorpb.FileDescriptorSet) []byte {
	f.Helper()
	data, err := proto.Marshal(set)
	if err != nil {
		f.Fatalf("marshal descriptor set: %v", err)
	}
	return data
}

func fuzzProtosetDescriptorSet() *descriptorpb.FileDescriptorSet {
	request := &descriptorpb.DescriptorProto{Name: new("Request")}
	response := &descriptorpb.DescriptorProto{Name: new("Response")}
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:    new("fuzz.proto"),
		Package: new("fuzz"),
		Syntax:  new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			request,
			response,
			{Name: new("Wrapped"), NestedType: []*descriptorpb.DescriptorProto{{Name: new("Inner")}}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("Echo"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       new("Do"),
				InputType:  new(".fuzz.Request"),
				OutputType: new(".fuzz.Response"),
			}},
		}},
	}}}
}

// fuzzFileCountSet builds one minimal named file per slot so the boundary on
// both sides of MaxFiles stays unique and resolvable inside the fuzz budget.
func fuzzFileCountSet(count int) *descriptorpb.FileDescriptorSet {
	files := make([]*descriptorpb.FileDescriptorProto, count)
	for index := range files {
		files[index] = &descriptorpb.FileDescriptorProto{
			Name:   new(fmt.Sprintf("%d.proto", index)),
			Syntax: new("proto3"),
		}
	}
	return &descriptorpb.FileDescriptorSet{File: files}
}

// fuzzNestingSet builds a single chain of nested messages of the given depth.
func fuzzNestingSet(depth int) *descriptorpb.FileDescriptorSet {
	root := &descriptorpb.DescriptorProto{Name: new("L0")}
	current := root
	for level := 1; level < depth; level++ {
		nested := &descriptorpb.DescriptorProto{Name: new(fmt.Sprintf("L%d", level))}
		current.NestedType = append(current.NestedType, nested)
		current = nested
	}
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:        new("nested.proto"),
		Syntax:      new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{root},
	}}}
}

// fuzzProtosetNestingDepth re-derives the deepest message nesting, counting a
// file's top-level messages as depth one.
func fuzzProtosetNestingDepth(set *descriptorpb.FileDescriptorSet) int {
	depth := 0
	var visit func(message *descriptorpb.DescriptorProto, level int)
	visit = func(message *descriptorpb.DescriptorProto, level int) {
		depth = max(depth, level)
		for _, nested := range message.GetNestedType() {
			visit(nested, level+1)
		}
	}
	for _, file := range set.GetFile() {
		for _, message := range file.GetMessageType() {
			visit(message, 1)
		}
	}
	return depth
}
