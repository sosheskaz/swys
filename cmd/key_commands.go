package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

var keyConversionTargets = map[string]asym.KeyFormat{
	"openssh":   asym.KeyFormatOpenSSH,
	"pkcs1-der": asym.KeyFormatPKCS1DER,
	"pkcs1-pem": asym.KeyFormatPKCS1PEM,
	"pkcs8-der": asym.KeyFormatPKCS8DER,
	"pkcs8-pem": asym.KeyFormatPKCS8PEM,
	"pkix-der":  asym.KeyFormatPKIXDER,
	"pkix-pem":  asym.KeyFormatPKIXPEM,
	"sec1-der":  asym.KeyFormatSEC1DER,
	"sec1-pem":  asym.KeyFormatSEC1PEM,
}

var keyFormatters = map[string]func() asym.KeyFormatter{
	"json": func() asym.KeyFormatter { return &asym.KeyJSONFormatter{Indent: true} },
	"text": func() asym.KeyFormatter { return &asym.KeyTextFormatter{} },
}

func newKeyPublicCmd() *cobra.Command {
	keyPublicCmd := binaryOutputCommand(&cobra.Command{
		Aliases: []string{"pub", "p"},
		Use:     "public",
		Short:   "Derive or canonicalize a public key",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := readKey(cmd)
			if err != nil {
				return err
			}
			encoded, err := key.Marshal(asym.KeyFormatPKIXPEM)
			if err != nil {
				return err
			}
			return writeKeyBytes(cmd, encoded, "public key")
		},
	}, true)
	return keyPublicCmd
}

func newKeyInspectCmd() *cobra.Command {
	keyInspectCmd := encodedInputCommand(structuredOutputCommand(&cobra.Command{
		Aliases: []string{"ins", "i"},
		Use:     "inspect",
		Short:   "Inspect public or private key metadata",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			formatter, err := keyFormatterFromCommand(cmd)
			if err != nil {
				return err
			}
			key, err := readKey(cmd)
			if err != nil {
				return err
			}
			info, err := key.Info()
			if err != nil {
				return err
			}
			return formatter.Format(info, cmd.OutOrStdout())
		},
	}, keyFormatNames))
	return keyInspectCmd
}

func newKeyConvertCmd() *cobra.Command {
	keyConvertCmd := binaryOutputCommand(&cobra.Command{
		Aliases: []string{"conv", "c"},
		Use:     "convert",
		Short:   "Convert a key to another standard container",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := readKey(cmd)
			if err != nil {
				return err
			}
			target, err := keyConversionTargetFromCommand(cmd)
			if err != nil {
				return err
			}
			encoded, err := key.Marshal(target)
			if err != nil {
				return err
			}
			return writeKeyBytes(cmd, encoded, "converted key")
		},
	}, true)
	keyConvertCmd.Flags().String(
		"to",
		"",
		"conversion target ("+strings.Join(keyConversionTargetNames(), ", ")+")",
	)
	if err := keyConvertCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
	registerFlagCompletion(keyConvertCmd, "to", keyConversionTargetNames)
	addCommandShape(keyConvertCmd, "key-convert")
	return keyConvertCmd
}

func readKey(cmd *cobra.Command) (*asym.Key, error) {
	data, err := readArtifact(cmd.InOrStdin(), maxKeyArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("read key input: %w", err)
	}
	key, err := asym.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key input: %w", err)
	}
	return key, nil
}

func writeKeyBytes(cmd *cobra.Command, data []byte, description string) error {
	if _, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write %s: %w", description, err)
	}
	return nil
}

func keyConversionTargetNames() []string {
	return sortedKeys(keyConversionTargets)
}

func keyPublicFormatNames() []string {
	names := make([]string, 0, len(keyConversionTargets))
	for name, format := range keyConversionTargets {
		if isPublicKeyFormat(format) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func isPublicKeyFormat(format asym.KeyFormat) bool {
	switch format {
	case asym.KeyFormatOpenSSH, asym.KeyFormatPKIXDER, asym.KeyFormatPKIXPEM:
		return true
	case asym.KeyFormatPKCS8PEM,
		asym.KeyFormatPKCS8DER,
		asym.KeyFormatPKCS1PEM,
		asym.KeyFormatPKCS1DER,
		asym.KeyFormatSEC1PEM,
		asym.KeyFormatSEC1DER:
		return false
	}
	return false
}

func keyPublicFormatFromCommand(cmd *cobra.Command) (asym.KeyFormat, error) {
	name, err := cmd.Flags().GetString("public-format")
	if err != nil {
		return "", fmt.Errorf("read public-format flag: %w", err)
	}
	target, ok := keyConversionTargets[name]
	if !ok || !isPublicKeyFormat(target) {
		return "", fmt.Errorf(
			"%w %q (valid: %s)",
			errUnknownKeyPublicFormat,
			name,
			strings.Join(keyPublicFormatNames(), ", "),
		)
	}
	return target, nil
}

func keyConversionTargetFromCommand(cmd *cobra.Command) (asym.KeyFormat, error) {
	name, err := cmd.Flags().GetString("to")
	if err != nil {
		return "", fmt.Errorf("read conversion target flag: %w", err)
	}
	target, ok := keyConversionTargets[name]
	if !ok {
		return "", fmt.Errorf(
			"%w %q (valid: %s)",
			errUnknownKeyConversionTarget,
			name,
			strings.Join(keyConversionTargetNames(), ", "),
		)
	}
	return target, nil
}

func keyFormatNames() []string {
	return sortedKeys(keyFormatters)
}

func keyFormatterFromCommand(cmd *cobra.Command) (asym.KeyFormatter, error) {
	name, err := cmd.Flags().GetString(formatFlagName)
	if err != nil {
		return nil, fmt.Errorf("read key format flag: %w", err)
	}
	constructor, ok := keyFormatters[name]
	if !ok {
		return nil, fmt.Errorf("%w %q (valid: %s)", errUnknownKeyFormat, name, strings.Join(keyFormatNames(), ", "))
	}
	return constructor(), nil
}

func validateKeyFlagsBeforeIO(cmd *cobra.Command) error {
	switch {
	case commandHasShape(cmd, "key-generate"):
		return validateKeyGenerateFlags(cmd)
	case commandHasShape(cmd, "key-convert"):
		_, err := keyConversionTargetFromCommand(cmd)
		return err
	default:
		return nil
	}
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
	algorithm, err := keyAlgorithmFromName(cmd.Flags().Arg(0))
	if err != nil {
		return err
	}
	if algorithm.aesBits != 0 {
		return fmt.Errorf("%w: --public-out is only valid for asymmetric keys", errInvalidKeyGenerateFlags)
	}
	if _, err := keyPublicFormatFromCommand(cmd); err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("read output flag: %w", err)
	}
	if output != "" {
		same, err := sameCommandPath(output, publicOut)
		if err != nil {
			return fmt.Errorf("compare private and public key outputs: %w", err)
		}
		if same {
			return fmt.Errorf("%w: --output %q and --public-out %q", errKeyOutputCollision, output, publicOut)
		}
	}

	info, err := os.Stat(publicOut)
	if err == nil && info.IsDir() {
		return fmt.Errorf("--public-out %q: %w", publicOut, errOutputIsDirectory)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect --public-out %q: %w", publicOut, err)
	}
	return nil
}
