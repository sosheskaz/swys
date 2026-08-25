package cmd

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

type keyAlgorithm struct {
	asymmetric  asym.KeyAlgorithm
	longName    string
	description string
	aesBits     int
}

var keyAlgorithms = map[string]keyAlgorithm{
	"aes128":  {longName: "aes-128", description: "AES-128 symmetric key", aesBits: 128},
	"aes192":  {longName: "aes-192", description: "AES-192 symmetric key", aesBits: 192},
	"aes256":  {longName: "aes-256", description: "AES-256 symmetric key", aesBits: 256},
	"ed25519": {description: "Ed25519 signing key", asymmetric: asym.KeyAlgorithmEd25519},
	"p256":    {longName: "ecdsa-p256", description: "ECDSA key on NIST P-256", asymmetric: asym.KeyAlgorithmECDSAP256},
	"p384":    {longName: "ecdsa-p384", description: "ECDSA key on NIST P-384", asymmetric: asym.KeyAlgorithmECDSAP384},
	"rsa2048": {longName: "rsa-2048", description: "RSA key with a 2048-bit modulus", asymmetric: asym.KeyAlgorithmRSA2048},
	"rsa4096": {longName: "rsa-4096", description: "RSA key with a 4096-bit modulus", asymmetric: asym.KeyAlgorithmRSA4096},
}

var keyCmd = &cobra.Command{
	Aliases: []string{"k"},
	Use:     "key",
	Short:   "Generate, inspect, and convert cryptographic keys",
	Long: `Generate, inspect, and convert cryptographic keys.
Asymmetric private-key generation uses PKCS#8 PEM. Key-consuming
commands accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key, or one
PKIX public key, in PEM or DER form. Inspection never prints private material.`,
}

var keyGenerateCmd = binaryOutputCommand(&cobra.Command{
	Aliases:           []string{"gen", "g"},
	Use:               "generate <algorithm>",
	Short:             "Generate a new cryptographic key",
	Long:              keyGenerateHelp(),
	Args:              validateKeyGenerateArgs,
	ValidArgsFunction: completeKeyAlgorithms,
	RunE: func(cmd *cobra.Command, args []string) error {
		algorithm, err := keyAlgorithmFromName(args[0])
		if err != nil {
			return err
		}
		if algorithm.aesBits != 0 {
			return generateAESKey(algorithm.aesBits, cmd.OutOrStdout())
		}

		privateKey, err := asym.GeneratePrivateKey(algorithm.asymmetric)
		if err != nil {
			return err
		}
		key, err := asym.NewKey(privateKey)
		if err != nil {
			return fmt.Errorf("validate generated private key: %w", err)
		}
		encoded, err := key.Marshal(asym.KeyFormatPKCS8PEM)
		if err != nil {
			return err
		}
		if _, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(encoded)); err != nil {
			return fmt.Errorf("write generated private key: %w", err)
		}
		return nil
	},
}, false)

// genkeyCmd is a one-release compatibility command for the former grammar.
var genkeyCmd = binaryOutputCommand(&cobra.Command{
	Use:    "genkey",
	Short:  "Generate a new AES key",
	Long:   "Deprecated: use npc key generate aesN instead. This compatibility command will be removed in a future release.",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		bits, err := cmd.Flags().GetInt("bits")
		if err != nil {
			return fmt.Errorf("read bits flag: %w", err)
		}
		if err := validateAESKeySize(bits); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(
			cmd.ErrOrStderr(),
			"warning: %s is deprecated; use npc key generate aes%d\n",
			cmd.CommandPath(),
			bits,
		); err != nil {
			return fmt.Errorf("write genkey deprecation warning: %w", err)
		}
		return writeAESKey(bits, cmd.OutOrStdout())
	},
}, false)

func keyAlgorithmNames() []string {
	return sortedKeys(keyAlgorithms)
}

func keyAlgorithmFromName(name string) (keyAlgorithm, error) {
	algorithm, ok := keyAlgorithms[name]
	if ok {
		return algorithm, nil
	}
	for _, algorithm := range keyAlgorithms {
		if algorithm.longName == name {
			return algorithm, nil
		}
	}
	return keyAlgorithm{}, fmt.Errorf("%w %q (short names: %s)", errUnknownKeyAlgorithm, name, strings.Join(keyAlgorithmNames(), ", "))
}

func keyGenerateHelp() string {
	var help strings.Builder
	help.WriteString("Generate a new cryptographic key. Short names are preferred.\n\nAlgorithms:\n")
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

func validateKeyGenerateArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	_, err := keyAlgorithmFromName(args[0])
	return err
}

func completeKeyAlgorithms(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := make([]string, 0, len(keyAlgorithms)*2)
	for _, name := range keyAlgorithmNames() {
		completions = append(completions, name)
		if longName := keyAlgorithms[name].longName; longName != "" {
			completions = append(completions, longName)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func generateAESKey(bits int, output io.Writer) error {
	if err := validateAESKeySize(bits); err != nil {
		return err
	}
	return writeAESKey(bits, output)
}

func validateAESKeySize(bits int) error {
	switch bits {
	case 128, 192, 256:
		return nil
	default:
		return fmt.Errorf("%w, got %d", errInvalidAESKeySize, bits)
	}
}

func writeAESKey(bits int, output io.Writer) error {
	if _, err := io.CopyN(output, rand.Reader, int64(bits/8)); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	aesCmd.AddCommand(genkeyCmd)
	genkeyCmd.Flags().IntP("bits", "b", 128, "AES key size in bits (128, 192, or 256)")
}
