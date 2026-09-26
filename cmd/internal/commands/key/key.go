package key

import (
	"embed"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	guidehelp "github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
)

//go:embed guides
var keyGuideFiles embed.FS

// NewCommand constructs the key command family for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	keyCmd := &cobra.Command{
		Aliases: []string{"k"},
		Use:     "key",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			return cobra.NoArgs(cmd, args)
		},
		RunE:  func(*cobra.Command, []string) error { return nil },
		Short: "Inspect and convert cryptographic keys",
		Long: `Inspect and convert cryptographic keys.
Key-consuming commands accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key, or one
PKIX public key, in PEM or DER form. Inspection never prints private material.`,
	}
	public := newKeyPublicCmd()
	inspect := newKeyInspectCmd()
	convert := newKeyConvertCmd()
	keyCmd.AddCommand(public, inspect, convert)
	lifecycle.Register(public, commandio.Behavior{
		Validate: func(cmd *cobra.Command) error {
			_, err := keyPublicTargetFromCommand(cmd, "to")
			if err != nil {
				return fmt.Errorf("validate key flags: %w", err)
			}
			return nil
		},
		Prepare:        prepareKeyPublicOutput,
		PreparesOutput: func(*cobra.Command) bool { return true },
	})
	lifecycle.Register(inspect, commandio.Behavior{})
	lifecycle.Register(convert, commandio.Behavior{
		Validate: func(cmd *cobra.Command) error {
			_, err := keyConversionTargetFromCommand(cmd)
			if err != nil {
				return fmt.Errorf("validate key flags: %w", err)
			}
			return nil
		},
		Prepare:        prepareKeyConversionOutput,
		PreparesOutput: func(*cobra.Command) bool { return true },
		Sensitive: func(cmd *cobra.Command) (bool, error) {
			target, err := keyConversionTargetFromCommand(cmd)
			if err != nil {
				return false, err
			}
			return !isPublicKeyFormat(target), nil
		},
	})
	if err := guidehelp.RegisterGuides(keyCmd, keyGuideFiles); err != nil {
		panic(err)
	}
	return keyCmd
}
