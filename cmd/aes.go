package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type aesCipherMode string

const (
	aesCipherModeCBC aesCipherMode = "cbc"
	aesCipherModeGCM aesCipherMode = "gcm"
)

var (
	errUnknownAESCipherMode  = errors.New("unknown AES cipher mode")
	errAADCipherMode         = errors.New("--aad is only valid with --cipher-mode gcm")
	errIVCipherMode          = errors.New("--iv is only valid with --cipher-mode cbc")
	errAESKeyOutputCollision = errors.New("AES keyfile and output collide")
	aesCipherModes           = map[string]aesCipherMode{
		string(aesCipherModeCBC): aesCipherModeCBC,
		string(aesCipherModeGCM): aesCipherModeGCM,
	}
)

func newAesCmd() *cobra.Command {
	aesCmd := &cobra.Command{
		Use:   "aes",
		Short: "AES encryption and decryption",
		Long: `Perform AES encryption and decryption using a specified key.
AES-GCM is the authenticated default; select AES-CBC explicitly for compatibility.
The length of the key implicitly determines the AES variant used (128, 192, or 256 bits).`,
	}
	aesCmd.AddCommand(newEncryptCmd(), newDecryptCmd(), newGenkeyCmd())
	return aesCmd
}

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().BytesBase64P("key", "k", nil, "key as a base64-encoded argument")
	cmd.Flags().StringP("keyfile", "K", "", "read the raw key from this file")
	if err := cmd.MarkFlagFilename("keyfile"); err != nil {
		panic(err)
	}
	cmd.MarkFlagsMutuallyExclusive("key", "keyfile")
	cmd.MarkFlagsOneRequired("key", "keyfile")
}

func addAESCipherFlags(cmd *cobra.Command) {
	cmd.Flags().String(
		"cipher-mode",
		string(aesCipherModeGCM),
		"AES cipher mode ("+strings.Join(aesCipherModeNames(), ", ")+")",
	)
	registerFlagCompletion(cmd, "cipher-mode", aesCipherModeNames)
	cmd.Flags().String("aad", "", "additional authenticated data for GCM")
}

func aesCipherModeNames() []string {
	return sortedKeys(aesCipherModes)
}

func aesCipherModeFromCommand(cmd *cobra.Command) (aesCipherMode, error) {
	name, err := cmd.Flags().GetString("cipher-mode")
	if err != nil {
		return "", fmt.Errorf("read cipher-mode flag: %w", err)
	}
	mode, ok := aesCipherModes[name]
	if !ok {
		return "", fmt.Errorf("%w %q (valid: %s)", errUnknownAESCipherMode, name, strings.Join(aesCipherModeNames(), ", "))
	}
	return mode, nil
}

func aesAADFromCommand(cmd *cobra.Command) ([]byte, error) {
	aad, err := cmd.Flags().GetString("aad")
	if err != nil {
		return nil, fmt.Errorf("read AAD flag: %w", err)
	}
	return []byte(aad), nil
}

func validateAESFlagsBeforeIO(cmd *cobra.Command) error {
	if cmd.Flags().Lookup("cipher-mode") == nil {
		return nil
	}
	mode, err := aesCipherModeFromCommand(cmd)
	if err != nil {
		return err
	}
	if mode == aesCipherModeCBC && cmd.Flags().Changed("aad") {
		return errAADCipherMode
	}
	if mode == aesCipherModeGCM && cmd.Flags().Changed("iv") {
		return errIVCipherMode
	}
	keyfile, err := cmd.Flags().GetString("keyfile")
	if err != nil {
		return fmt.Errorf("read keyfile flag: %w", err)
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("read output flag: %w", err)
	}
	if keyfile != "" && output != "" {
		same, err := sameCommandPath(keyfile, output)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("%w: --keyfile %q and --output %q", errAESKeyOutputCollision, keyfile, output)
		}
	}
	return nil
}

func getKey(cmd *cobra.Command) ([]byte, error) {
	keyFlag := cmd.Flags().Lookup("key")
	keyFileFlag := cmd.Flags().Lookup("keyfile")
	if keyFlag.Changed == keyFileFlag.Changed {
		return nil, errKeySelection
	}

	if keyFlag.Changed {
		key, err := cmd.Flags().GetBytesBase64("key")
		if err != nil {
			return nil, fmt.Errorf("read key flag: %w", err)
		}
		return key, nil
	}

	keyFilePath, err := cmd.Flags().GetString("keyfile")
	if err != nil {
		return nil, fmt.Errorf("read keyfile flag: %w", err)
	}
	// The path is intentionally supplied by the CLI user.
	key, err := readArtifactFile(keyFilePath, maxAESKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read keyfile %q: %w", keyFilePath, err)
	}
	return key, nil
}
