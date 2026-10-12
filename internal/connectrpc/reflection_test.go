package connectrpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestReflectionFetchesMissingTransitiveImportsOnce(t *testing.T) {
	t.Parallel()
	root := &descriptorpb.FileDescriptorProto{Name: new("root.proto"), Dependency: []string{"middle.proto", "leaf.proto"}}
	middle := &descriptorpb.FileDescriptorProto{Name: new("middle.proto"), Dependency: []string{"leaf.proto"}}
	leaf := &descriptorpb.FileDescriptorProto{Name: new("leaf.proto")}
	var requested []string
	set, err := collectDescriptors(func(name string) ([]*descriptorpb.FileDescriptorProto, error) {
		requested = append(requested, name)
		if name == "middle.proto" {
			return []*descriptorpb.FileDescriptorProto{middle}, nil
		}
		return []*descriptorpb.FileDescriptorProto{leaf}, nil
	}, []*descriptorpb.FileDescriptorProto{root})
	require.NoError(t, err)
	assert.Equal(t, []string{"middle.proto", "leaf.proto"}, requested)
	assert.Equal(t, []*descriptorpb.FileDescriptorProto{root, middle, leaf}, set.File)
}

func TestReflectionRejectsInconsistentImportReplies(t *testing.T) {
	t.Parallel()
	root := &descriptorpb.FileDescriptorProto{Name: new("root.proto"), Dependency: []string{"missing.proto"}}
	for _, files := range [][]*descriptorpb.FileDescriptorProto{
		{},
		{{Name: new("root.proto"), Package: new("conflict")}},
		{{Name: new("")}},
	} {
		_, err := collectDescriptors(func(string) ([]*descriptorpb.FileDescriptorProto, error) { return files, nil }, []*descriptorpb.FileDescriptorProto{root})
		require.ErrorIs(t, err, errReflection)
	}
}
