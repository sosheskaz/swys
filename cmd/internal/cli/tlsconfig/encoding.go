package tlsconfig

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
)

// AddArtifactEncodingFlags registers independent outer codecs for TLS credentials.
func AddArtifactEncodingFlags(cmd *cobra.Command, applicable func(*cobra.Command, []string) bool) {
	for _, source := range []string{CAFlagName, CertFlagName, KeyFlagName} {
		name := source + "-encoding"
		cmd.Flags().String(name, encoding.Raw, "outer encoding of --"+source+" ("+strings.Join(encoding.Names(), ", ")+")")
		if err := cmd.RegisterFlagCompletionFunc(name, func(command *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
			path, err := command.Flags().GetString(source)
			if err != nil || path == "" || !applicable(command, args) || !artifactSourceApplicable(command, source) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var values []string
			for _, codec := range encoding.Names() {
				if strings.HasPrefix(codec, prefix) {
					values = append(values, cobra.CompletionWithDesc(codec, commandio.ByteEncodingDescriptions[codec]))
				}
			}
			return values, cobra.ShellCompDirectiveNoFileComp
		}); err != nil {
			panic(err)
		}
	}
}

// ValidateArtifactSources rejects codecs and competing stdin owners before artifact I/O.
// Each family supplies its effective payload ownership and its validation error identity.
func ValidateArtifactSources(cmd *cobra.Command, applicable, payloadStdin bool, invalid error) error {
	owner := ""
	if payloadStdin {
		owner = "payload"
	}
	for _, source := range []string{CAFlagName, CertFlagName, KeyFlagName} {
		name := source + "-encoding"
		if _, err := artifactDecoder(cmd, source); err != nil {
			return fmt.Errorf("--%s: %w", name, err)
		}
		path, err := cmd.Flags().GetString(source)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", source, err)
		}
		if cmd.Flags().Changed(name) {
			if path == "" {
				return fmt.Errorf("%w: --%s requires --%s", invalid, name, source)
			}
			if !applicable {
				return fmt.Errorf("%w: --%s requires TLS", invalid, name)
			}
		}
		if path == "-" {
			if owner != "" {
				return fmt.Errorf("%w: --%s and %s cannot both read stdin", invalid, source, owner)
			}
			owner = "--" + source
		}
	}
	return nil
}

// UsesStdin reports exact dash credentials without touching the filesystem or input.
func UsesStdin(cmd *cobra.Command) bool {
	for _, name := range []string{CAFlagName, CertFlagName, KeyFlagName} {
		path, err := cmd.Flags().GetString(name)
		if err == nil && path == "-" {
			return true
		}
	}
	return false
}

func artifactDecoder(cmd *cobra.Command, source string) (encoding.InputDecoder, error) {
	// Keep callers without companion flags compatible with the raw loader.
	if cmd.Flags().Lookup(source+"-encoding") == nil {
		return encoding.GetInputDecoder(encoding.Raw)
	}
	name, err := cmd.Flags().GetString(source + "-encoding")
	if err != nil {
		return nil, fmt.Errorf("read %s-encoding flag: %w", source, err)
	}
	return encoding.GetInputDecoder(name)
}

func readCommandArtifact(cmd *cobra.Command, source, path string, limit int64) ([]byte, error) {
	decoder, err := artifactDecoder(cmd, source)
	if err != nil {
		return nil, err
	}
	data, err := artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), path, decoder, limit)
	if err != nil {
		return nil, fmt.Errorf("read --%s %q: %w", source, path, err)
	}
	return data, nil
}

// RegisterArtifactEncodingCompletion probes only flags before contextual flag-name completion.
func RegisterArtifactEncodingCompletion(lifecycle *commandio.Lifecycle, build func() *cobra.Command, applicable func(*cobra.Command, []string) bool) {
	lifecycle.RegisterCompletion(func(completionCmd *cobra.Command, args []string) {
		if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
			return
		}
		completed := args[:len(args)-1]
		probeRoot := commandio.NewProbeRoot()
		probeRoot.AddCommand(build())
		probe, probeArgs, err := probeRoot.Find(completed)
		if err != nil || probe.Flags().Lookup(CAEncodingFlagName) == nil {
			return
		}
		if err := probe.ParseFlags(probeArgs); err != nil {
			return
		}
		actual, _, err := completionCmd.Root().Find(completed)
		if err != nil || actual.Flags().Lookup(CAEncodingFlagName) == nil {
			return
		}
		SetArtifactEncodingVisibility(actual, probe, applicable(probe, probe.Flags().Args()))
	})
}

// SetArtifactEncodingVisibility hides companion flags when their source or transport is absent.
func SetArtifactEncodingVisibility(actual, probe *cobra.Command, applicable bool) {
	for _, source := range []string{CAFlagName, CertFlagName, KeyFlagName} {
		path, err := probe.Flags().GetString(source)
		if flag := actual.Flags().Lookup(source + "-encoding"); flag != nil {
			flag.Hidden = err != nil || path == "" || !applicable || !artifactSourceApplicable(probe, source)
		}
	}
}

func artifactSourceApplicable(cmd *cobra.Command, source string) bool {
	insecure := cmd.Flag("insecure")
	return source != CAFlagName || insecure == nil || insecure.Value.String() == "false"
}
