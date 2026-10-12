package protoschema

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Template builds an editable request with nested objects but no guessed oneofs.
// The caller serializes it with protobuf JSON's EmitUnpopulated option.
func Template(descriptor protoreflect.MessageDescriptor) (proto.Message, error) {
	message := dynamicpb.NewMessage(descriptor)
	budget := MaxBytes
	fields := 4096
	if err := populateTemplate(message, make(map[protoreflect.FullName]bool), 0, &budget, &fields); err != nil {
		return nil, err
	}
	return message, nil
}

func populateTemplate(message protoreflect.Message, visiting map[protoreflect.FullName]bool, depth int, budget, remaining *int) error {
	descriptor := message.Descriptor()
	if known := wellKnownMessage(descriptor.FullName()); known != nil {
		return populateWellKnown(message, known)
	}
	visiting[descriptor.FullName()] = true
	defer delete(visiting, descriptor.FullName())
	for i := range descriptor.Fields().Len() {
		field := descriptor.Fields().Get(i)
		if oneof := field.ContainingOneof(); oneof != nil && !oneof.IsSynthetic() {
			continue
		}
		*remaining--
		*budget -= len(field.JSONName()) + len(field.Default().String()) + 64
		if value := field.DefaultEnumValue(); value != nil {
			*budget -= len(value.Name())
		}
		if *remaining < 0 || *budget < 0 {
			return fmt.Errorf("%w: request template expansion is too large", ErrLimit)
		}
		if field.IsList() || field.IsMap() {
			continue
		}
		if field.Message() == nil {
			// Explicit optional/required scalars need presence to expose their default.
			if field.HasPresence() {
				message.Set(field, field.Default())
			}
			continue
		}
		if depth >= 3 || visiting[field.Message().FullName()] {
			continue
		}
		nested := message.NewField(field).Message()
		if err := populateTemplate(nested, visiting, depth+1, budget, remaining); err != nil {
			return err
		}
		message.Set(field, protoreflect.ValueOfMessage(nested))
	}
	return nil
}

func populateWellKnown(message protoreflect.Message, known proto.Message) error {
	descriptor := message.Descriptor()
	// ProtoJSON selects special encoders by name and assumes the standard
	// fields exist. A supplied descriptor must satisfy those assumptions.
	if !sameFieldShape(descriptor, known.ProtoReflect().Descriptor()) {
		return fmt.Errorf("%w: malformed well-known message %s", ErrSymbol, descriptor.FullName())
	}
	if descriptor.FullName() == "google.protobuf.Value" {
		message.Set(descriptor.Fields().ByName("null_value"), protoreflect.ValueOfEnum(0))
	}
	return nil
}

var wellKnownMessages = map[protoreflect.FullName]proto.Message{
	"google.protobuf.Any": &anypb.Any{}, "google.protobuf.Timestamp": &timestamppb.Timestamp{},
	"google.protobuf.Duration": &durationpb.Duration{}, "google.protobuf.FieldMask": &fieldmaskpb.FieldMask{},
	"google.protobuf.Struct": &structpb.Struct{}, "google.protobuf.ListValue": &structpb.ListValue{},
	"google.protobuf.Value": &structpb.Value{}, "google.protobuf.Empty": &emptypb.Empty{},
	"google.protobuf.DoubleValue": &wrapperspb.DoubleValue{}, "google.protobuf.FloatValue": &wrapperspb.FloatValue{},
	"google.protobuf.Int64Value": &wrapperspb.Int64Value{}, "google.protobuf.UInt64Value": &wrapperspb.UInt64Value{},
	"google.protobuf.Int32Value": &wrapperspb.Int32Value{}, "google.protobuf.UInt32Value": &wrapperspb.UInt32Value{},
	"google.protobuf.BoolValue": &wrapperspb.BoolValue{}, "google.protobuf.StringValue": &wrapperspb.StringValue{},
	"google.protobuf.BytesValue": &wrapperspb.BytesValue{},
}

func wellKnownMessage(name protoreflect.FullName) proto.Message {
	return wellKnownMessages[name]
}

func sameFieldShape(actual, expected protoreflect.MessageDescriptor) bool {
	if actual.Fields().Len() != expected.Fields().Len() {
		return false
	}
	for i := range expected.Fields().Len() {
		want := expected.Fields().Get(i)
		got := actual.Fields().ByNumber(want.Number())
		if got == nil || got.Name() != want.Name() || got.Kind() != want.Kind() || got.Cardinality() != want.Cardinality() || got.IsMap() != want.IsMap() {
			return false
		}
		if (got.ContainingOneof() == nil) != (want.ContainingOneof() == nil) {
			return false
		}
		if want.ContainingOneof() != nil && got.ContainingOneof().Name() != want.ContainingOneof().Name() {
			return false
		}
		if want.Message() != nil && got.Message().FullName() != want.Message().FullName() || want.Enum() != nil && got.Enum().FullName() != want.Enum().FullName() {
			return false
		}
	}
	return true
}
