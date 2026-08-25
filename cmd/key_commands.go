package cmd

import (
	"bytes"
	"fmt"
	"io"
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

var keyPublicCmd = binaryOutputCommand(&cobra.Command{
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

var keyInspectCmd = encodedInputCommand(structuredOutputCommand(&cobra.Command{
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

var keyConvertCmd = binaryOutputCommand(&cobra.Command{
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

func readKey(cmd *cobra.Command) (*asym.Key, error) {
	data, err := io.ReadAll(cmd.InOrStdin())
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
	switch cmd {
	case keyConvertCmd:
		_, err := keyConversionTargetFromCommand(cmd)
		return err
	default:
		return nil
	}
}

func init() {
	keyCmd.AddCommand(keyPublicCmd, keyInspectCmd, keyConvertCmd)
	keyConvertCmd.Flags().String(
		"to",
		"",
		"conversion target ("+strings.Join(keyConversionTargetNames(), ", ")+")",
	)
	if err := keyConvertCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}
	registerFlagCompletion(keyConvertCmd, "to", keyConversionTargetNames)
}
