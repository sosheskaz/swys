package cert

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
)

const certCADataFlagName = "ca-data"

func addCertificateCAFlags(cmd *cobra.Command) {
	cmd.Flags().String("ca", "", "trust anchors file path (PEM or DER), or - for stdin; use --ca-data for literal content")
	cmd.Flags().String(certCADataFlagName, "", "literal trust anchors (PEM or encoded PEM/DER); decoded by --ca-encoding")
	cmd.Flags().Bool("system-ca", false, "combine system roots with --ca or --ca-data (custom roots otherwise replace system roots)")
	cmd.MarkFlagsMutuallyExclusive("ca", certCADataFlagName)
	if err := cmd.MarkFlagFilename("ca"); err != nil {
		panic(err)
	}
	mustRegisterCertificateCompletion(cmd, "ca", completeCertificateArtifact("ca"))
	mustRegisterCertificateCompletion(cmd, certCADataFlagName, cobra.NoFileCompletions)
	addCertificateArtifactEncodingFlags(cmd, "ca")
}

func validateCertificateCAFlags(cmd *cobra.Command) error {
	data, err := cmd.Flags().GetString(certCADataFlagName)
	if err != nil {
		return fmt.Errorf("read ca-data flag: %w", err)
	}
	if cmd.Flags().Changed(certCADataFlagName) && data == "" {
		return fmt.Errorf("%w: --ca-data requires nonempty literal certificate content", errInvalidCertificateFlags)
	}
	return validateCertificateArtifactEncodings(cmd, "ca")
}

func validateCertInspectFlags(cmd *cobra.Command) error {
	if err := validateInspectionFlags(cmd); err != nil {
		return err
	}
	if err := validateCertificateCAFlags(cmd); err != nil {
		return err
	}
	if err := validateCertificateChainInputSelection(cmd, "ca"); err != nil {
		return err
	}
	return certinput.ValidatePaths(cmd, "ca")
}

func validateCertificateChainInputSelection(cmd *cobra.Command, sources ...string) error {
	inputPath, err := cmd.Flags().GetString("input")
	if err != nil {
		return fmt.Errorf("read input flag: %w", err)
	}
	owners := 0
	if inputPath == "" || inputPath == "-" {
		owners++
	}
	for _, name := range sources {
		path, err := cmd.Flags().GetString(name)
		if err != nil {
			return fmt.Errorf("read %s flag: %w", name, err)
		}
		if path == "-" {
			owners++
		}
	}
	if owners > 1 {
		return fmt.Errorf("%w: certificate chain and --%s must have at most one stdin owner", ErrCertificateInputSelection, strings.Join(sources, ", --"))
	}
	return nil
}

func certVerificationRoots(cmd *cobra.Command) (*x509.CertPool, error) {
	caPath, err := cmd.Flags().GetString("ca")
	if err != nil {
		return nil, fmt.Errorf("read ca flag: %w", err)
	}
	caData, err := cmd.Flags().GetString(certCADataFlagName)
	if err != nil {
		return nil, fmt.Errorf("read ca-data flag: %w", err)
	}
	includeSystem, err := cmd.Flags().GetBool("system-ca")
	if err != nil {
		return nil, fmt.Errorf("read system-ca flag: %w", err)
	}
	if caPath == "" && caData == "" && cmd.Name() == certInspectCommandName {
		return nil, nil //nolint:nilnil // nil Roots preserve inspection's default platform verifier.
	}
	var roots *x509.CertPool
	if (caPath == "" && caData == "") || includeSystem {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		roots = roots.Clone()
	} else {
		roots = x509.NewCertPool()
	}
	var certificates []*x509.Certificate
	source := "ca"
	if caData != "" {
		source = certCADataFlagName
		certificates, err = readCertificateCAData(cmd, caData)
	} else if caPath != "" {
		certificates, err = readCertificateBundle(cmd, "ca", caPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read --%s: %w", source, err)
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	return roots, nil
}

func readCertificateCAData(cmd *cobra.Command, value string) ([]*x509.Certificate, error) {
	decoder, err := certificateArtifactDecoder(cmd, "ca")
	if err != nil {
		return nil, err
	}
	data, err := artifact.Read(decoder(strings.NewReader(value)), artifact.MaxCertificateBytes)
	if err != nil {
		return nil, err
	}
	return parseCertificateArtifact(data)
}
