package cmd

import (
	"crypto/aes"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func newEncryptCmd() *cobra.Command {
	encryptCmd := binaryOutputCommand(&cobra.Command{
		Use:     "encrypt [plaintext]",
		Short:   "Encrypt with AES-GCM by default or AES-CBC explicitly",
		Aliases: []string{"enc", "e"},
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := commandInput(cmd, args)
			if err != nil {
				return err
			}

			key, err := getKey(cmd)
			if err != nil {
				return err
			}
			mode, err := aesCipherModeFromCommand(cmd)
			if err != nil {
				return err
			}
			switch mode {
			case aesCipherModeGCM:
				return encryptGCM(cmd, key, input)
			case aesCipherModeCBC:
				cipher, err := crypter.NewAESCrypter(key)
				if err != nil {
					return err
				}
				iv, err := getIV(cmd, aes.BlockSize)
				if err != nil {
					return err
				}
				return cipher.Encrypt(iv, input, cmd.OutOrStdout())
			default:
				return fmt.Errorf("%w %q", errUnknownAESCipherMode, mode)
			}
		},
	}, true)
	addKeyFlags(encryptCmd)
	addAESCipherFlags(encryptCmd)
	encryptCmd.Flags().Bool("raw", false, "use legacy single-message AES-GCM format (64 MiB limit)")
	encryptCmd.Flags().String("chunk-size", "1M", "maximum plaintext bytes per stream segment (64 through 64MiB)")
	registerAESNoFileFlagCompletion(encryptCmd, "chunk-size")
	encryptCmd.Flags().BytesBase64("iv", nil, "CBC initialization vector as base64; random when omitted")
	registerAESNoFileFlagCompletion(encryptCmd, "iv")
	encryptCmd.ValidArgsFunction = cobra.NoFileCompletions
	return encryptCmd
}

func getIV(cmd *cobra.Command, blockSize int) ([]byte, error) {
	ivFlag := cmd.Flags().Lookup("iv")
	if !ivFlag.Changed {
		return generateIV(blockSize)
	}

	iv, err := cmd.Flags().GetBytesBase64("iv")
	if err != nil {
		return nil, fmt.Errorf("read IV flag: %w", err)
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", crypter.ErrInvalidIVLength, blockSize, len(iv))
	}
	return iv, nil
}

func encryptGCM(cmd *cobra.Command, key []byte, input io.Reader) error {
	raw, err := cmd.Flags().GetBool("raw")
	if err != nil {
		return fmt.Errorf("read raw flag: %w", err)
	}
	aad, err := aesAADFromCommand(cmd)
	if err != nil {
		return err
	}
	if raw {
		cipher, err := crypter.NewAESGCMCrypter(key)
		if err != nil {
			return err
		}
		return cipher.Encrypt(input, cmd.OutOrStdout(), aad)
	}
	stream, err := crypter.NewAESStreamingCrypter(key)
	if err != nil {
		return err
	}
	chunkText, err := cmd.Flags().GetString("chunk-size")
	if err != nil {
		return fmt.Errorf("read chunk-size flag: %w", err)
	}
	chunkSize, err := parseAESChunkSize(chunkText)
	if err != nil {
		return err
	}
	return stream.Encrypt(input, cmd.OutOrStdout(), aad, chunkSize)
}
