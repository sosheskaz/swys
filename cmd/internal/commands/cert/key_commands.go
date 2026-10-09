package cert

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/internal/asym"
)

var keyConversionTargets = map[string]asym.KeyFormat{
	string(asym.KeyFormatOpenSSH): asym.KeyFormatOpenSSH,
	"pkcs1-der":                   asym.KeyFormatPKCS1DER,
	"pkcs1-pem":                   asym.KeyFormatPKCS1PEM,
	"pkcs8-der":                   asym.KeyFormatPKCS8DER,
	"pkcs8-pem":                   asym.KeyFormatPKCS8PEM,
	string(asym.KeyFormatPKIXDER): asym.KeyFormatPKIXDER,
	string(asym.KeyFormatPKIXPEM): asym.KeyFormatPKIXPEM,
	"sec1-der":                    asym.KeyFormatSEC1DER,
	"sec1-pem":                    asym.KeyFormatSEC1PEM,
}

var keyFormatters = map[string]func() asym.KeyFormatter{
	formatPlain: func() asym.KeyFormatter { return &asym.KeyTextFormatter{} },
	"json":      func() asym.KeyFormatter { return &asym.KeyJSONFormatter{Indent: true} },
	"text":      func() asym.KeyFormatter { return &asym.KeyTextFormatter{} },
}

func newKeyPublicCmd() *cobra.Command {
	keyPublicCmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use:   "key-public",
		Short: "Derive or canonicalize a public key",
		Long: `Derive the public component of a private key or canonicalize an existing public key.
The --to flag selects PKIX PEM, PKIX DER, or one canonical OpenSSH
authorized_keys entry. It defaults to PKIX PEM.
Inputs accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key or a PKIX public key in PEM or DER,
or one unencrypted OpenSSH private key or authorized_keys public entry.`,
		Example: `  swys cert key-public --input private.pem --output public.pem
  swys cert key-public --input id_ed25519 --to openssh --output id_ed25519.pub
  swys cert key-public --input private.pem --to pkix-der --output public.der`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			encoded, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			return writeKey(output, encoded, "public key")
		},
	}, true)
	keyPublicCmd.Flags().String(
		"to",
		string(asym.KeyFormatPKIXPEM),
		"public-key target ("+strings.Join(keyPublicFormatNames(), ", ")+")",
	)
	commandio.RegisterFlagCompletion(keyPublicCmd, "to", keyPublicFormatCompletions)
	commandio.AddShape(keyPublicCmd, "key-public")
	keyPublicCmd.ValidArgsFunction = cobra.NoFileCompletions
	return keyPublicCmd
}

func newKeyInspectCmd() *cobra.Command {
	keyInspectCmd := commandio.EncodedInputCommand(commandio.StructuredOutputCommand(&cobra.Command{
		Use:   "key-inspect",
		Short: "Inspect public or private key metadata",
		Long: `Inspect public or private key metadata without printing private material.
Inputs accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key or a PKIX public key in PEM or DER,
or one unencrypted OpenSSH private key or authorized_keys public entry.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			prepared, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			return writeKey(output, prepared, "key metadata")
		},
	}, keyFormatNames))
	commandio.AddOutputEncodingFlag(keyInspectCmd)
	keyInspectCmd.ValidArgsFunction = cobra.NoFileCompletions
	return keyInspectCmd
}

func newKeyConvertCmd() *cobra.Command {
	keyConvertCmd := commandio.BinaryOutputCommand(&cobra.Command{
		Use:   "key-convert",
		Short: "Convert a key to another standard container",
		Long: `Convert a key to another standard container without changing whether it is private or public.
Use cert key-public to derive public material from a private key.
Inputs accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key or a PKIX public key in PEM or DER,
or one unencrypted OpenSSH private key or authorized_keys public entry.`,
		Example: `  swys cert key-convert --input id_ed25519.pub --to pkix-pem
  swys cert key-convert --input private.pem --to pkcs8-der --output private.der`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			encoded, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			return writeKey(output, encoded, "converted key")
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
	commandio.RegisterFlagCompletion(keyConvertCmd, "to", keyConversionTargetCompletions)
	commandio.AddShape(keyConvertCmd, "key-convert")
	keyConvertCmd.ValidArgsFunction = cobra.NoFileCompletions
	return keyConvertCmd
}

func readKeyFrom(input io.Reader) (*asym.Key, error) {
	data, err := artifact.Read(input, artifact.MaxKeyBytes)
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
	return writeKey(cmd.OutOrStdout(), data, description)
}

func writeKey(output io.Writer, data []byte, description string) error {
	if _, err := io.Copy(output, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write %s: %w", description, err)
	}
	return nil
}

func keyConversionTargetNames() []string {
	return slices.Sorted(maps.Keys(keyConversionTargets))
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

func keyPublicFormatCompletions() []string {
	return keyTargetCompletions(keyPublicFormatNames())
}

func keyConversionTargetCompletions() []string {
	return keyTargetCompletions(keyConversionTargetNames())
}

func keyTargetCompletions(names []string) []string {
	completions := make([]string, 0, len(names))
	for _, name := range names {
		completions = append(completions, cobra.CompletionWithDesc(name, keyTargetDescription(name)))
	}
	return completions
}

func keyTargetDescription(name string) string {
	switch name {
	case string(asym.KeyFormatOpenSSH):
		return "OpenSSH public key"
	case "pkcs1-der":
		return "PKCS #1 private key in binary DER"
	case "pkcs1-pem":
		return "PKCS #1 private key in PEM"
	case "pkcs8-der":
		return "PKCS #8 private key in binary DER"
	case "pkcs8-pem":
		return "PKCS #8 private key in PEM"
	case string(asym.KeyFormatPKIXDER):
		return "PKIX public key in binary DER"
	case string(asym.KeyFormatPKIXPEM):
		return "PKIX public key in PEM"
	case "sec1-der":
		return "SEC 1 EC private key in binary DER"
	case "sec1-pem":
		return "SEC 1 EC private key in PEM"
	default:
		return ""
	}
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

func keyPublicTargetFromCommand(cmd *cobra.Command, flagName string) (asym.KeyFormat, error) {
	name, err := cmd.Flags().GetString(flagName)
	if err != nil {
		return "", fmt.Errorf("read %s flag: %w", flagName, err)
	}
	return keyPublicTarget(name)
}

func keyPublicTarget(name string) (asym.KeyFormat, error) {
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
			ErrUnknownKeyConversionTarget,
			name,
			strings.Join(keyConversionTargetNames(), ", "),
		)
	}
	return target, nil
}

func keyFormatNames() []string {
	return slices.Sorted(maps.Keys(keyFormatters))
}

func keyFormatterFromCommand(cmd *cobra.Command) (asym.KeyFormatter, error) {
	name, err := cmd.Flags().GetString(commandio.FormatFlagName)
	if err != nil {
		return nil, fmt.Errorf("read key format flag: %w", err)
	}
	constructor, ok := keyFormatters[name]
	if !ok {
		return nil, fmt.Errorf("%w %q (valid: %s)", ErrUnknownKeyFormat, name, strings.Join(keyFormatNames(), ", "))
	}
	formatter := constructor()
	if text, isText := formatter.(*asym.KeyTextFormatter); isText {
		options := presentation.Output(cmd)
		text.Presentation = &options
	}
	return formatter, nil
}

func prepareKeyPublicOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	key, err := readKeyFrom(input)
	if err != nil {
		return nil, err
	}
	target, err := keyPublicTargetFromCommand(cmd, "to")
	if err != nil {
		return nil, err
	}
	encoded, err := key.Marshal(target)
	if err != nil {
		return nil, fmt.Errorf("serialize public key as %s: %w", target, err)
	}
	return encoded, nil
}

func prepareKeyConversionOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	key, err := readKeyFrom(input)
	if err != nil {
		return nil, err
	}
	target, err := keyConversionTargetFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	targetIsPublic := isPublicKeyFormat(target)
	if key.IsPrivate() == targetIsPublic {
		if key.IsPrivate() {
			return nil, fmt.Errorf(
				"%w: cannot convert private key to public target %q; use swys cert key-public --to %s",
				asym.ErrInvalidKeyConversion,
				target,
				target,
			)
		}
		return nil, fmt.Errorf(
			"%w: cannot convert public key to private target %q",
			asym.ErrInvalidKeyConversion,
			target,
		)
	}
	encoded, err := key.Marshal(target)
	if err != nil {
		return nil, fmt.Errorf("serialize key as %s: %w", target, err)
	}
	return encoded, nil
}

func prepareKeyInspectionOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	formatter, err := keyFormatterFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	key, err := readKeyFrom(input)
	if err != nil {
		return nil, err
	}
	info, err := key.Info()
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := formatter.Format(info, &output); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
