package testcmd

import (
	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/commands/dns"
	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

// NewDNSRoot mounts an injected DNS command with the same global flags and
// lifecycle used by the production root.
func NewDNSRoot(dependencies dnsquery.Dependencies) *cobra.Command {
	lifecycle := commandio.NewLifecycle()
	root := &cobra.Command{
		Use:           "npc",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(command *cobra.Command, args []string) error {
			return lifecycle.PreRun(command, args)
		},
		PersistentPostRunE: func(command *cobra.Command, _ []string) error {
			return commandio.Close(command)
		},
	}
	commandio.AddRootFlags(root)
	root.AddCommand(dns.NewCommand(lifecycle, dependencies))
	return root
}
