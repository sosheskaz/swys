package cert

import (
	"crypto/x509"
	"embed"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

//go:embed guides
var certGuideFiles embed.FS

// NewCommand constructs the certificate command family for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	certCmd := &cobra.Command{
		Aliases: []string{"x509", "certificate", "x.509"},
		Use:     "cert",
		Short:   "Manage X.509 certificates and asymmetric keys",
	}
	help.ConfigureBranch(certCmd)
	inspect := newCertInspectCmd()
	connect := newConnectCmd()
	create := newCertCreateCmd()
	csr := newCertCSRCmd()
	verify := newCertVerifyCmd()
	match := newCertMatchCmd()
	keygen := newCertKeygenCmd()
	keyPublic := newKeyPublicCmd()
	keyInspect := newKeyInspectCmd()
	keyConvert := newKeyConvertCmd()
	certCmd.AddCommand(inspect, connect, create, csr, verify, match, keygen, keyPublic, keyInspect, keyConvert)
	lifecycle.RegisterCompletion(func(command *cobra.Command, args []string) {
		prepareCertificateCompletion(command, args, create)
	})
	lifecycle.Register(keygen, commandio.Behavior{SupportsOutput: true, Validate: validateCertificateFlags(validateCertKeygenFlags)})
	lifecycle.Register(keyPublic, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
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
	lifecycle.Register(keyInspect, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate: func(cmd *cobra.Command) error {
			_, err := keyFormatterFromCommand(cmd)
			return err
		},
		Prepare:        prepareKeyInspectionOutput,
		PreparesOutput: func(*cobra.Command) bool { return true },
	})
	lifecycle.Register(keyConvert, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
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
	lifecycle.Register(inspect, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate:       validateInspectionFlags,
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare:        prepareInspectedCertificates,
	})
	lifecycle.Register(connect, commandio.Behavior{
		SupportsOutput: true,
		Validate: func(cmd *cobra.Command) error {
			if err := commandio.ValidateNetworkTimeout(cmd); err != nil {
				return fmt.Errorf("validate network flags: %w", err)
			}
			return validateInspectionFlags(cmd)
		},
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare:        prepareConnectedCertificates,
	})
	lifecycle.Register(create, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate:       validateCertificateFlags(validateCertificateCreateFlags),
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare:        prepareCertificateOutput,
	})
	lifecycle.Register(csr, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate:       validateCertificateFlags(validateCertificateCSRFlags),
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare:        prepareCertificateRequestOutput,
	})
	lifecycle.Register(verify, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate:       validateCertificateFlags(validateCertVerifyFlags),
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare: func(cmd *cobra.Command, input io.Reader) ([]byte, error) {
			return prepareCertificateReport(cmd, input, prepareCertVerifyReport)
		},
	})
	lifecycle.Register(match, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Validate:       validateCertificateFlags(validateCertMatchFlags),
		PreparesOutput: func(*cobra.Command) bool { return true },
		Prepare: func(cmd *cobra.Command, input io.Reader) ([]byte, error) {
			return prepareCertificateReport(cmd, input, prepareCertMatchReport)
		},
	})
	if err := help.RegisterGuides(certCmd, certGuideFiles); err != nil {
		panic(err)
	}
	return certCmd
}

func validateCertificateFlags(validate func(*cobra.Command) error) func(*cobra.Command) error {
	return func(cmd *cobra.Command) error {
		if err := validate(cmd); err != nil {
			return fmt.Errorf("validate certificate flags: %w", err)
		}
		return nil
	}
}

func certificateCreateUsesCSR(cmd *cobra.Command) bool {
	value, err := cmd.Flags().GetString(csrFlagName)
	return err == nil && value != ""
}

func newCertInspectCmd() *cobra.Command {
	certInspectCmd := commandio.StructuredOutputCommand(&cobra.Command{
		Use:   "inspect",
		Short: "Inspect X.509 certificates",
		Args:  cobra.NoArgs,
		RunE:  runPreparedInspection,
	}, certFormatNames)
	commandio.AddInputEncodingFlag(certInspectCmd)
	commandio.AddOutputEncodingFlag(certInspectCmd)
	addCertificateSelection(certInspectCmd, asym.SelectFullChain)
	certInspectCmd.ValidArgsFunction = cobra.NoFileCompletions
	return certInspectCmd
}

func prepareInspectedCertificates(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	data, err := artifact.Read(input, artifact.MaxCertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("read certificate input: %w", err)
	}
	certs, err := parseCertificateArtifact(data)
	if err != nil {
		return nil, err
	}
	return prepareInspection(cmd, certs, &x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}, "input")
}
