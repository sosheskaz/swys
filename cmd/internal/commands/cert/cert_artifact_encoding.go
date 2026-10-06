package cert

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
)

func addCertificateArtifactEncodingFlags(cmd *cobra.Command, sources ...string) {
	for _, name := range sources {
		flag := name + "-encoding"
		cmd.Flags().String(flag, encoding.Raw, "outer encoding of --"+name+" ("+strings.Join(encoding.Names(), ", ")+")")
		mustRegisterCertificateCompletion(cmd, flag, func(command *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if !certificateArtifactEncodingApplicable(command, name) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			values := commandio.CompletionsWithDescriptions(encoding.Names(), commandio.ByteEncodingDescriptions)
			return completionPrefixMatches(values, prefix), cobra.ShellCompDirectiveNoFileComp
		})
	}
}

func certificateArtifactEncodingApplicable(cmd *cobra.Command, name string) bool {
	source, err := cmd.Flags().GetString(name)
	if err != nil || source == "" {
		return false
	}
	if cmd.Name() != certVerifyCommandName && source == "-" && cmd.Flags().Changed(commandio.InputEncodingFlagName) {
		return false
	}
	if mode, ok := certificateCompletionMode(cmd); ok {
		return mode.artifactAllowed(name)
	}
	return true
}

func certificateArtifactDecoder(cmd *cobra.Command, name string) (encoding.InputDecoder, error) {
	value, err := cmd.Flags().GetString(name + "-encoding")
	if err != nil {
		return nil, fmt.Errorf("read %s-encoding flag: %w", name, err)
	}
	return encoding.GetInputDecoder(value)
}

func validateCertificateArtifactEncodings(cmd *cobra.Command, names ...string) error {
	for _, name := range names {
		if _, err := certificateArtifactDecoder(cmd, name); err != nil {
			return fmt.Errorf("--%s-encoding: %w", name, err)
		}
		source, err := cmd.Flags().GetString(name)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", name, err)
		}
		if cmd.Flags().Changed(name+"-encoding") && source == "" {
			return fmt.Errorf("%w: --%s-encoding requires --%s", errInvalidCertificateFlags, name, name)
		}
	}
	return nil
}

func readCertificateEncodedOperand(cmd *cobra.Command, input io.Reader, name, path string, limit int64) ([]byte, error) {
	decoder, err := certificateArtifactDecoder(cmd, name)
	if err != nil {
		return nil, err
	}
	if path == "-" && cmd.Flags().Changed(commandio.InputEncodingFlagName) {
		// commandio already decoded the sole main-stream operand.
		return artifact.Read(input, limit)
	}
	return artifact.ReadEncodedSource(cmd.Context(), input, path, decoder, limit)
}
