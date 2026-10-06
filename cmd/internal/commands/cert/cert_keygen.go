package cert

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/asym"
)

var generatedPublicFormats = map[string]asym.KeyFormat{
	string(asym.KeyFormatOpenSSH): asym.KeyFormatOpenSSH,
	string(asym.KeyFormatPKIXDER): asym.KeyFormatPKIXDER,
	string(asym.KeyFormatPKIXPEM): asym.KeyFormatPKIXPEM,
}

func generatedPublicFormatFromCommand(cmd *cobra.Command) (asym.KeyFormat, error) {
	name, err := cmd.Flags().GetString("public-format")
	if err != nil {
		return "", fmt.Errorf("read public-format flag: %w", err)
	}
	format, ok := generatedPublicFormats[name]
	if !ok {
		return "", fmt.Errorf("%w %q (valid: %s)", errUnknownKeyPublicFormat, name, strings.Join(generatedPublicFormatNames(), ", "))
	}
	return format, nil
}

func generatedPublicFormatNames() []string {
	return []string{string(asym.KeyFormatOpenSSH), string(asym.KeyFormatPKIXDER), string(asym.KeyFormatPKIXPEM)}
}

func newCertKeygenCmd() *cobra.Command {
	cmd := commandio.SensitiveBinaryOutputCommand(&cobra.Command{
		Use:   "keygen",
		Short: "Generate a certificate private key",
		Long:  certKeygenHelp(),
		Args:  cobra.NoArgs,
		RunE:  runCertKeygen,
	}, false)
	cmd.Flags().StringP("algorithm", "a", "ed25519", "private-key algorithm ("+strings.Join(keyAlgorithmNames(), ", ")+")")
	cmd.Flags().StringP("public-out", "P", "", "write the corresponding public key to a file")
	cmd.Flags().String("public-format", string(asym.KeyFormatPKIXPEM), "format for --public-out ("+strings.Join(generatedPublicFormatNames(), ", ")+")")
	if err := cmd.MarkFlagFilename("public-out"); err != nil {
		panic(err)
	}
	if err := cmd.RegisterFlagCompletionFunc("algorithm", completeCertKeyAlgorithms); err != nil {
		panic(err)
	}
	if err := cmd.RegisterFlagCompletionFunc("public-format", completeGeneratedPublicFormats); err != nil {
		panic(err)
	}
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func completeCertKeyAlgorithms(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	completions := make([]string, 0, len(keyAlgorithms)*2)
	for _, name := range keyAlgorithmNames() {
		algorithm := keyAlgorithms[name]
		completions = append(completions, cobra.CompletionWithDesc(name, algorithm.description))
		if algorithm.longName != "" {
			completions = append(completions, cobra.CompletionWithDesc(algorithm.longName, algorithm.description))
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeGeneratedPublicFormats(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return []string{
		cobra.CompletionWithDesc(string(asym.KeyFormatOpenSSH), "OpenSSH public key"),
		cobra.CompletionWithDesc(string(asym.KeyFormatPKIXDER), "PKIX public key in binary DER"),
		cobra.CompletionWithDesc(string(asym.KeyFormatPKIXPEM), "PKIX public key in PEM"),
	}, cobra.ShellCompDirectiveNoFileComp
}

func validateCertKeygenFlags(cmd *cobra.Command) error {
	name, err := cmd.Flags().GetString("algorithm")
	if err != nil {
		return fmt.Errorf("read algorithm flag: %w", err)
	}
	if _, err := keyAlgorithmFromName(name); err != nil {
		return err
	}
	return validateKeyGenerateFlags(cmd)
}

type keyAlgorithm struct {
	asymmetric  asym.KeyAlgorithm
	longName    string
	description string
}

var keyAlgorithms = map[string]keyAlgorithm{
	"ed25519": {description: "Ed25519 signing key", asymmetric: asym.KeyAlgorithmEd25519},
	"p256":    {longName: "ecdsa-p256", description: "ECDSA key on NIST P-256", asymmetric: asym.KeyAlgorithmECDSAP256},
	"p384":    {longName: "ecdsa-p384", description: "ECDSA key on NIST P-384", asymmetric: asym.KeyAlgorithmECDSAP384},
	"rsa2048": {longName: "rsa-2048", description: "RSA key with a 2048-bit modulus", asymmetric: asym.KeyAlgorithmRSA2048},
	"rsa4096": {longName: "rsa-4096", description: "RSA key with a 4096-bit modulus", asymmetric: asym.KeyAlgorithmRSA4096},
}

func runCertKeygen(cmd *cobra.Command, _ []string) error {
	algorithmName, err := cmd.Flags().GetString("algorithm")
	if err != nil {
		return fmt.Errorf("read algorithm flag: %w", err)
	}
	algorithm, err := keyAlgorithmFromName(algorithmName)
	if err != nil {
		return err
	}

	privateKey, err := asym.GeneratePrivateKey(algorithm.asymmetric)
	if err != nil {
		return err
	}
	key, err := asym.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("validate generated private key: %w", err)
	}
	privateEncoded, err := key.Marshal(asym.KeyFormatPKCS8PEM)
	if err != nil {
		return err
	}

	publicOut, err := cmd.Flags().GetString("public-out")
	if err != nil {
		return fmt.Errorf("read public-out flag: %w", err)
	}
	var publicEncoded []byte
	if publicOut != "" {
		format, err := generatedPublicFormatFromCommand(cmd)
		if err != nil {
			return err
		}
		publicEncoded, err = key.Marshal(format)
		if err != nil {
			return fmt.Errorf("marshal generated public key: %w", err)
		}
	}

	if _, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(privateEncoded)); err != nil {
		return fmt.Errorf("write generated private key: %w", err)
	}
	if publicOut == "" {
		return nil
	}
	if err := writeGeneratedPublicKey(publicOut, publicEncoded); err != nil {
		privateOut, flagErr := cmd.Flags().GetString("output")
		if flagErr != nil {
			return errors.Join(err, fmt.Errorf("read output flag: %w", flagErr))
		}
		privateOut = commandio.NormalizeMainStreamPath(privateOut)
		if privateOut == "" {
			return fmt.Errorf("write generated public key after emitting private key: %w", err)
		}
		return fmt.Errorf("write generated public key; private key retained at %q: %w", privateOut, err)
	}
	return nil
}

func writeGeneratedPublicKey(path string, encoded []byte) (err error) {
	file, err := commandio.OpenOutput(path, commandio.OutputOptions{})
	if err != nil {
		return fmt.Errorf("open --public-out %q: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close --public-out %q: %w", path, closeErr))
		}
	}()
	if _, err := io.Copy(file, bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("write --public-out %q: %w", path, err)
	}
	return nil
}

func keyAlgorithmNames() []string {
	return slices.Sorted(maps.Keys(keyAlgorithms))
}

func keyAlgorithmFromName(name string) (keyAlgorithm, error) {
	algorithm, ok := keyAlgorithms[name]
	if ok {
		return algorithm, nil
	}
	for _, algorithm := range keyAlgorithms {
		if algorithm.longName != "" && algorithm.longName == name {
			return algorithm, nil
		}
	}
	return keyAlgorithm{}, fmt.Errorf("%w %q (short names: %s)", ErrUnknownKeyAlgorithm, name, strings.Join(keyAlgorithmNames(), ", "))
}

func certKeygenHelp() string {
	var help strings.Builder
	help.WriteString("Generate a new certificate private key. For asymmetric keys, --public-out writes " +
		"the matching public key in the selected --public-format. Short algorithm names are preferred.\n\nAlgorithms:\n")
	for _, name := range keyAlgorithmNames() {
		algorithm := keyAlgorithms[name]
		help.WriteString("  ")
		help.WriteString(name)
		help.WriteString(": ")
		help.WriteString(algorithm.description)
		if algorithm.longName != "" {
			help.WriteString(" (long: ")
			help.WriteString(algorithm.longName)
			help.WriteByte(')')
		}
		help.WriteByte('\n')
	}
	return strings.TrimSuffix(help.String(), "\n")
}

func validateKeyGenerateFlags(cmd *cobra.Command) error {
	publicOut, err := cmd.Flags().GetString("public-out")
	if err != nil {
		return fmt.Errorf("read public-out flag: %w", err)
	}
	if publicOut == "" {
		return validateMissingKeyPublicOutput(cmd)
	}
	if publicOut == "-" {
		return fmt.Errorf("%w: --public-out must name a file path, not -", errInvalidKeyGenerateFlags)
	}
	return validateKeyPublicOutput(cmd, publicOut)
}

func validateMissingKeyPublicOutput(cmd *cobra.Command) error {
	if cmd.Flags().Changed("public-out") {
		return fmt.Errorf("%w: --public-out must name a file path", errInvalidKeyGenerateFlags)
	}
	if cmd.Flags().Changed("public-format") {
		return fmt.Errorf("%w: --public-format requires --public-out", errInvalidKeyGenerateFlags)
	}
	return nil
}

func validateKeyPublicOutput(cmd *cobra.Command, publicOut string) error {
	algorithmName, err := cmd.Flags().GetString("algorithm")
	if err != nil {
		return fmt.Errorf("read algorithm flag: %w", err)
	}
	_, err = keyAlgorithmFromName(algorithmName)
	if err != nil {
		return err
	}
	if _, err := generatedPublicFormatFromCommand(cmd); err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("read output flag: %w", err)
	}
	output = commandio.NormalizeMainStreamPath(output)
	if output != "" {
		same, err := artifact.SamePath(output, publicOut)
		if err != nil {
			return fmt.Errorf("compare private and public key outputs: %w", err)
		}
		if same {
			return fmt.Errorf("%w: --output %q and --public-out %q", ErrKeyOutputCollision, output, publicOut)
		}
	}

	info, err := os.Stat(publicOut)
	if err == nil && info.IsDir() {
		return fmt.Errorf("--public-out %q: %w", publicOut, commandio.ErrOutputIsDirectory)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect --public-out %q: %w", publicOut, err)
	}
	return nil
}
