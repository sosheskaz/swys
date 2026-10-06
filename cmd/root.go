package cmd

import (
	"context"
	"embed"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
	"github.com/sosheskaz/swys/cmd/internal/commands/aes"
	"github.com/sosheskaz/swys/cmd/internal/commands/cert"
	"github.com/sosheskaz/swys/cmd/internal/commands/dns"
	grpccommand "github.com/sosheskaz/swys/cmd/internal/commands/grpc"
	"github.com/sosheskaz/swys/cmd/internal/commands/hash"
	"github.com/sosheskaz/swys/cmd/internal/commands/http"
	"github.com/sosheskaz/swys/cmd/internal/commands/net"
	"github.com/sosheskaz/swys/internal/dnsquery"
	"github.com/sosheskaz/swys/internal/version"
)

//go:embed guides
var rootGuideFiles embed.FS

const versionFlagName = "version"

func newRootCmd() *cobra.Command {
	return newRootCmdWithDNSDependencies(defaultDNSDependencies())
}

func defaultDNSDependencies() dnsquery.Dependencies {
	return dnsquery.DefaultDependencies()
}

// NewCommand constructs a fresh, fully configured command tree.
func NewCommand() *cobra.Command {
	return newRootCmd()
}

func newRootCmdWithDNSDependencies(dnsDeps dnsquery.Dependencies) *cobra.Command {
	return newRootCmdWithGuideDependencies(dnsDeps, help.DefaultDependencies())
}

func newRootCmdWithGuideDependencies(dnsDeps dnsquery.Dependencies, guideDeps help.Dependencies) *cobra.Command {
	lifecycle := commandio.NewLifecycle()
	rootCmd := &cobra.Command{
		Use:           "swys",
		Short:         "SwYS — A sysadmin's Swiss Army knife.",
		Version:       version.Get().String(),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if prepareQuietCompletion(cmd, args) {
				return nil
			}
			if help.IsGuideCommand(cmd) {
				lifecycle.PrepareCompletion(cmd, args)
				return nil
			}
			return lifecycle.PreRun(cmd, args)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return commandio.Close(cmd)
		},
	}
	rootCmd.Flags().BoolP(versionFlagName, "V", false, "version for "+rootCmd.DisplayName())
	if err := rootCmd.Flags().SetAnnotation(versionFlagName, cobra.FlagSetByCobraAnnotation, []string{"true"}); err != nil {
		panic(err)
	}
	commandio.AddRootFlags(rootCmd)
	httpCmd := http.NewCommand(lifecycle)
	rootCmd.AddCommand(
		aes.NewCommand(lifecycle), cert.NewCommand(lifecycle),
		hash.NewCommand(lifecycle), net.NewCommand(lifecycle), httpCmd,
		dns.NewCommand(lifecycle, dnsDeps), grpccommand.NewCommand(lifecycle),
	)
	http.RegisterBodyCompletionGroups(httpCmd)
	configureCompletionGeneration(rootCmd)
	help.Configure(rootCmd, guideDeps, func(command *cobra.Command, render func()) {
		presentReferenceHelp(lifecycle, command, render)
	})
	registerSharedCompletions(rootCmd, lifecycle)
	if err := help.RegisterGuides(rootCmd, rootGuideFiles); err != nil {
		panic(err)
	}
	return rootCmd
}

func presentReferenceHelp(lifecycle *commandio.Lifecycle, command *cobra.Command, referenceHelp func()) {
	net.ReferenceHelp(command, func() { lifecycle.ReferenceHelp(command, referenceHelp) })
}

// Execute runs the root command.
func Execute() error {
	return executeCommand(newRootCmd())
}

// ExecuteContext runs the root command with ctx. A run that a signal from
// WithInterrupt cuts short returns an error that ExitCode maps to 128+signal.
func ExecuteContext(ctx context.Context) error {
	return executeContext(ctx, newRootCmd()) //nolint:contextcheck // cobra hands ctx to commands through the root
}

func executeContext(ctx context.Context, root *cobra.Command) error {
	root.SetContext(ctx)
	return interrupt.Attribute(ctx, executeCommand(root))
}

func executeCommand(root *cobra.Command) error {
	return commandio.Execute(root)
}
