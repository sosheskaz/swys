package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var aesCmd = &cobra.Command{
	Use:   "aes",
	Short: "AES encryption and decryption",
	Long: `Perform AES encryption and decryption using a specified key.
The length of the key implicitly determines the AES variant used (128, 192, or 256 bits).`,
}

func addKeyFlags(cmd *cobra.Command) pflag.FlagSet {
	var flags pflag.FlagSet

	cmd.Flags().BytesBase64P("key", "k", []byte{}, "key to use to decrypt the input, as an argument, in base64.")
	cmd.Flags().StringP("keyfile", "K", "", "key to use to decrypt the input, read from the given file.")
	cmd.MarkFlagFilename("keyfile")
	cmd.MarkFlagsMutuallyExclusive("key", "keyfile")
	cmd.MarkFlagsOneRequired("key", "keyfile")

	return flags
}

func init() {
	rootCmd.AddCommand(aesCmd)
}

func getKey(cmd *cobra.Command) ([]byte, error) {
	keyFlag := cmd.Flags().Lookup("key")
	keyfile := cmd.Flags().Lookup("keyfile")
	if keyFlag.Changed == keyfile.Changed {
		return nil, errors.New("exactly one of either key or keyfile must be set")
	}

	if keyFlag.Changed {
		keyBase64, err := cmd.Flags().GetBytesBase64("key")
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}
		return keyBase64, nil
	}

	keyfilePath, err := cmd.Flags().GetString("keyfile")
	if err != nil {
		return nil, fmt.Errorf("failed to get keyfile: %w", err)
	}
	key, err := os.ReadFile(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile %q: %w", keyfilePath, err)
	}
	return key, nil
}
