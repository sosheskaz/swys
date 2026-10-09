package cert

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
)

func addCertificateArtifactEncodingFlags(cmd *cobra.Command, sources ...string) {
	for _, name := range sources {
		flag := name + "-encoding"
		source := "--" + name
		if name == "ca" && cmd.Flags().Lookup(certCADataFlagName) != nil {
			source += " or --ca-data"
		}
		cmd.Flags().String(flag, encoding.Raw, "outer encoding of "+source+" ("+strings.Join(encoding.Names(), ", ")+")")
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
	if err != nil {
		return false
	}
	if name == "ca" && cmd.Flags().Lookup(certCADataFlagName) != nil {
		data, err := cmd.Flags().GetString(certCADataFlagName)
		if err == nil && data != "" {
			return true
		}
	}
	if source == "" {
		return false
	}
	if cmd.Name() != certVerifyCommandName && cmd.Name() != certInspectCommandName && source == "-" && cmd.Flags().Changed(commandio.InputEncodingFlagName) {
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
			if name == "ca" && cmd.Flags().Lookup(certCADataFlagName) != nil {
				if cmd.Flags().Changed(certCADataFlagName) {
					continue
				}
				return fmt.Errorf("%w: --ca-encoding requires --ca or --ca-data", errInvalidCertificateFlags)
			}
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
