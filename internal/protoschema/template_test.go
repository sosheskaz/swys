package protoschema_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sosheskaz/swys/internal/protoschema"
)

func TestTemplateShowsEditableDefaultsAndLeavesOneofsUnselected(t *testing.T) {
	t.Parallel()
	file := &descriptorpb.FileDescriptorProto{
		Name: new("template.proto"), Package: new("example"), Syntax: new("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name:  new("Mode"),
			Value: []*descriptorpb.EnumValueDescriptorProto{{Name: new("UNSPECIFIED"), Number: new(int32(0))}},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Request"), OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: new("identity")}},
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: new("name"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
				{Name: new("count"), Number: new(int32(2)), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()},
				{Name: new("enabled"), Number: new(int32(3)), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum()},
				{
					Name: new("modes"), Number: new(int32(4)), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type: descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(), TypeName: new(".example.Mode"),
				},
				{
					Name: new("labels"), Number: new(int32(5)), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: new(".example.Request.LabelsEntry"),
				},
				{Name: new("nested"), Number: new(int32(6)), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: new(".example.Nested")},
				{Name: new("recursive"), Number: new(int32(7)), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: new(".example.Request")},
				{Name: new("id"), Number: new(int32(8)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), OneofIndex: new(int32(0))},
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name: new("LabelsEntry"), Options: &descriptorpb.MessageOptions{MapEntry: new(true)},
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: new("key"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: new("value"), Number: new(int32(2)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
				},
			}},
		}, {Name: new("Nested"), Field: []*descriptorpb.FieldDescriptorProto{
			{Name: new("text"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
		}}},
	}
	descriptor, err := protodesc.NewFile(file, nil)
	require.NoError(t, err)
	message, err := protoschema.Template(descriptor.Messages().ByName("Request"))
	require.NoError(t, err)
	data, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(message)
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"","count":"0","enabled":false,"modes":[],"labels":{},"nested":{"text":""},"recursive":null}`, string(data))
	require.NoError(t, protojson.Unmarshal(data, message), "template must be valid protobuf JSON")
}

func TestTemplateUsesProtobufDefaultsAndWellKnownJSON(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		message proto.Message
		want    string
	}{
		{"timestamp", &timestamppb.Timestamp{}, `"1970-01-01T00:00:00Z"`},
		{"unselected Any", &anypb.Any{}, `{}`},
		{"null value", &structpb.Value{}, `null`},
		{"struct", &structpb.Struct{}, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			message, err := protoschema.Template(test.message.ProtoReflect().Descriptor())
			require.NoError(t, err)
			data, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(message)
			require.NoError(t, err)
			assert.JSONEq(t, test.want, string(data))
			require.NoError(t, protojson.Unmarshal(data, message))
		})
	}
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: new("defaults.proto"), Syntax: new("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: new("Request"), Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name: new("count"), Number: new(int32(1)), Label: descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
				Type: descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(), DefaultValue: new("12"),
			},
		}}},
	}, nil)
	require.NoError(t, err)
	message, err := protoschema.Template(file.Messages().Get(0))
	require.NoError(t, err)
	data, err := protojson.Marshal(message)
	require.NoError(t, err)
	assert.JSONEq(t, `{"count":12}`, string(data))
}

func TestTemplateBoundsExpansion(t *testing.T) {
	t.Parallel()
	file := &descriptorpb.FileDescriptorProto{Name: new("deep.proto"), Syntax: new("proto3")}
	for depth := range 5 {
		message := &descriptorpb.DescriptorProto{Name: new(fmt.Sprintf("Level%d", depth))}
		if depth < 4 {
			message.Field = []*descriptorpb.FieldDescriptorProto{{
				Name: new("child"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
				TypeName: new(fmt.Sprintf("Level%d", depth+1)),
			}}
		}
		file.MessageType = append(file.MessageType, message)
	}
	descriptor, err := protodesc.NewFile(file, nil)
	require.NoError(t, err)
	message, err := protoschema.Template(descriptor.Messages().Get(0))
	require.NoError(t, err)
	data, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(message)
	require.NoError(t, err)
	assert.JSONEq(t, `{"child":{"child":{"child":{"child":null}}}}`, string(data))

	wide := &descriptorpb.DescriptorProto{Name: new("Wide")}
	for i := range 4097 {
		wide.Field = append(wide.Field, &descriptorpb.FieldDescriptorProto{
			Name: new(fmt.Sprintf("field%d", i)), Number: new(int32(i + 1)),
			Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum(),
		})
	}
	descriptor, err = protodesc.NewFile(&descriptorpb.FileDescriptorProto{Name: new("wide.proto"), MessageType: []*descriptorpb.DescriptorProto{wide}}, nil)
	require.NoError(t, err)
	_, err = protoschema.Template(descriptor.Messages().Get(0))
	require.ErrorIs(t, err, protoschema.ErrLimit)
}

func TestTemplateRejectsMalformedWellKnownDescriptor(t *testing.T) {
	t.Parallel()
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: new("value.proto"), Package: new("google.protobuf"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: new("Value")}},
	}, new(protoregistry.Files))
	require.NoError(t, err)
	_, err = protoschema.Template(file.Messages().ByName(protoreflect.Name("Value")))
	require.Error(t, err)
}
