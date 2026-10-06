package aes

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/crypter"
)

func newAESKeygenCmd() *cobra.Command {
	cmd := commandio.SensitiveBinaryOutputCommand(&cobra.Command{
		Use:   commandKeygen,
		Short: "Generate a raw AES key or Tink keyset",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			prepared, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			n, err := output.Write(prepared)
			if err != nil {
				return fmt.Errorf("write AES key: %w", err)
			}
			if n != len(prepared) {
				return fmt.Errorf("write AES key: %w", io.ErrShortWrite)
			}
			return nil
		},
	}, false)
	cmd.Flags().IntP("bits", "b", 256, "AES key size in bits (128 or 256)")
	cmd.Flags().String("key-format", "raw", "key format ("+strings.Join(keyFormatNames(), ", ")+")")
	addTinkParameterFlags(cmd)
	registerAESValueCompletion(cmd, "key-format", keyFormatNames)
	registerAESValueCompletion(cmd, "bits", func() []string { return []string{"128", "256"} })
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func validateAESKeygenFlags(cmd *cobra.Command) error {
	bits, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return fmt.Errorf("read bits flag: %w", err)
	}
	if err := validateAESKeySize(bits); err != nil {
		return err
	}
	format, err := keyFormatFlag(cmd, "key-format")
	if err != nil {
		return err
	}
	_, err = tinkParamsFromCommand(cmd, format, bits)
	return err
}

func generateAESKey(bits int, output io.Writer) error {
	if err := validateAESKeySize(bits); err != nil {
		return err
	}
	if _, err := io.CopyN(output, rand.Reader, int64(bits/8)); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}
	return nil
}

func validateAESKeySize(bits int) error {
	switch bits {
	case 128, 256:
		return nil
	default:
		return fmt.Errorf("%w, got %d", crypter.ErrInvalidAESKeySize, bits)
	}
}
