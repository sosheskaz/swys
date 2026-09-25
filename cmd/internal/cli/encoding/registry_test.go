package encoding_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
)

func TestByteEncodingRegistryDrivesHelpErrorsAndCompletion(t *testing.T) { //nolint:paralleltest // mutates a package-level encoding registry
	t.Cleanup(encoding.RegisterTestEncoding("fake"))

	command := commandio.BinaryOutputCommand(&cobra.Command{Use: "registry-test"}, true)
	for _, flagName := range []string{commandio.EncodingFlagName, commandio.InputEncodingFlagName} {
		flag := command.Flags().Lookup(flagName)
		require.NotNil(t, flag, "%s flag not registered", flagName)
		assert.Contains(t, flag.Usage, "fake", "%s usage", flagName)
		completion, ok := command.GetFlagCompletionFunc(flagName)
		require.True(t, ok, "%s has no completion function", flagName)
		values, directive := completion(command, nil, "")
		assert.True(t, slices.ContainsFunc(values, func(value string) bool {
			name, _, _ := strings.Cut(value, "\t")
			return name == "fake"
		}), "%s completions = %v", flagName, values)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "%s directive", flagName)
	}

	_, err := encoding.GetOutputEncoder("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fake", "output error = %v", err)
	_, err = encoding.GetInputDecoder("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fake", "input error = %v", err)
}
