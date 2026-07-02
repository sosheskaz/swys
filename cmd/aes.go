package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var aesCmd = &cobra.Command{
	Use:   "aes",
	Short: "AES encryption and decryption",
	Long: `Perform AES encryption and decryption using a specified key.
The length of the key implicitly determines the AES variant used (128, 192, or 256 bits).`,
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

func init() {
	rootCmd.AddCommand(aesCmd)
}

func getKey(cmd *cobra.Command) ([]byte, error) {
	keyFlag := cmd.Flags().Lookup("key")
	keyFileFlag := cmd.Flags().Lookup("keyfile")
	if keyFlag.Changed == keyFileFlag.Changed {
		return nil, errors.New("exactly one of key or keyfile must be set")
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
	key, err := os.ReadFile(keyFilePath) //nolint:gosec // reading an explicitly user-selected CLI path is intended
	if err != nil {
		return nil, fmt.Errorf("read keyfile %q: %w", keyFilePath, err)
	}
	return key, nil
}
