// Package protoschema loads bounded protobuf descriptor sets for RPC tools.
package protoschema

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Limits apply to schemas independently of application message limits.
const (
	MaxBytes     = 16 << 20
	MaxFiles     = 1024
	MaxDepth     = 100
	MaxWireBytes = MaxBytes * 2
)

// ErrLimit identifies a schema that exceeds the bounded discovery budget.
var ErrLimit = errors.New("protobuf descriptor limit exceeded")

// ErrSymbol identifies an absent or inapplicable schema symbol.
var ErrSymbol = errors.New("unsupported protobuf symbol")

// Schema contains resolved descriptors and a sorted service list.
type Schema struct {
	Files    *protoregistry.Files
	Services []string
}

// New resolves a complete descriptor set after checking its resource limits.
func New(set *descriptorpb.FileDescriptorSet) (*Schema, error) {
	if err := Validate(set); err != nil {
		return nil, err
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("resolve protobuf descriptors: %w", err)
	}
	services := []string{}
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if err = validateKnownMessages(file.Messages()); err != nil {
			return false
		}
		for i := range file.Services().Len() {
			services = append(services, string(file.Services().Get(i).FullName()))
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(services)
	return &Schema{Files: files, Services: services}, nil
}

func validateKnownMessages(messages protoreflect.MessageDescriptors) error {
	for i := range messages.Len() {
		message := messages.Get(i)
		if known := wellKnownMessage(message.FullName()); known != nil && !sameFieldShape(message, known.ProtoReflect().Descriptor()) {
			return fmt.Errorf("%w: malformed well-known message %s", ErrSymbol, message.FullName())
		}
		if err := validateKnownMessages(message.Messages()); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks aggregate bytes, file count, and message nesting before resolution.
func Validate(set *descriptorpb.FileDescriptorSet) error {
	if len(set.GetFile()) > MaxFiles {
		return fmt.Errorf("%w: set has %d files, maximum is %d", ErrLimit, len(set.GetFile()), MaxFiles)
	}
	total := 0
	type item struct {
		message *descriptorpb.DescriptorProto
		depth   int
	}
	for _, file := range set.GetFile() {
		total += proto.Size(file)
		if total > MaxBytes {
			return fmt.Errorf("%w: descriptors exceed %d bytes", ErrLimit, MaxBytes)
		}
		stack := make([]item, 0, len(file.GetMessageType()))
		for _, message := range file.GetMessageType() {
			stack = append(stack, item{message: message, depth: 1})
		}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current.depth > MaxDepth {
				return fmt.Errorf("%w: message nesting exceeds %d", ErrLimit, MaxDepth)
			}
			for _, nested := range current.message.GetNestedType() {
				stack = append(stack, item{message: nested, depth: current.depth + 1})
			}
		}
	}
	return nil
}

// Read bounds the wire input before parsing a FileDescriptorSet.
func Read(reader io.Reader) (*descriptorpb.FileDescriptorSet, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxWireBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read protoset: %w", err)
	}
	if len(data) > MaxWireBytes {
		return nil, fmt.Errorf("%w: protoset file is too large", ErrLimit)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("parse protoset: %w", err)
	}
	if err := Validate(set); err != nil {
		return nil, err
	}
	return set, nil
}

// Method resolves a SERVICE/METHOD selector.
func (schema *Schema) Method(selector string) (protoreflect.MethodDescriptor, error) {
	serviceName, methodName, _ := strings.Cut(strings.TrimPrefix(selector, "/"), "/")
	descriptor, err := schema.Files.FindDescriptorByName(protoreflect.FullName(serviceName))
	if err != nil {
		return nil, fmt.Errorf("find service %q: %w", serviceName, err)
	}
	service, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a service", ErrSymbol, serviceName)
	}
	method := service.Methods().ByName(protoreflect.Name(methodName))
	if method == nil {
		return nil, fmt.Errorf("%w: %q has no method %q", ErrSymbol, serviceName, methodName)
	}
	return method, nil
}

// DescriptorProto returns the standard protobuf representation of a descriptor.
func DescriptorProto(descriptor protoreflect.Descriptor) (proto.Message, error) {
	switch value := descriptor.(type) {
	case protoreflect.MessageDescriptor:
		return protodesc.ToDescriptorProto(value), nil
	case protoreflect.FieldDescriptor:
		return protodesc.ToFieldDescriptorProto(value), nil
	case protoreflect.OneofDescriptor:
		return protodesc.ToOneofDescriptorProto(value), nil
	case protoreflect.EnumDescriptor:
		return protodesc.ToEnumDescriptorProto(value), nil
	case protoreflect.EnumValueDescriptor:
		return protodesc.ToEnumValueDescriptorProto(value), nil
	case protoreflect.ServiceDescriptor:
		return protodesc.ToServiceDescriptorProto(value), nil
	case protoreflect.MethodDescriptor:
		return protodesc.ToMethodDescriptorProto(value), nil
	case protoreflect.FileDescriptor:
		return protodesc.ToFileDescriptorProto(value), nil
	default:
		return nil, fmt.Errorf("%w: descriptor type %T", ErrSymbol, descriptor)
	}
}
