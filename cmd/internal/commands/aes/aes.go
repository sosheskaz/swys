// Package aes constructs the AES encryption and decryption commands.
package aes

import (
	"context"
	"crypto/aes"
	"embed"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/internal/crypter"
)

//go:embed guides
var aesGuideFiles embed.FS

type aesCipherMode string

const (
	aesCipherModeCBC aesCipherMode = "cbc"
	aesCipherModeGCM aesCipherMode = "gcm"
)

var aesCipherModes = map[string]aesCipherMode{
	string(aesCipherModeCBC): aesCipherModeCBC,
	string(aesCipherModeGCM): aesCipherModeGCM,
}

var aesCipherModeDescriptions = map[aesCipherMode]string{
	aesCipherModeCBC: "compatibility mode",
	aesCipherModeGCM: "authenticated default",
}

// NewCommand constructs the AES command family for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	aesCmd := &cobra.Command{
		Use:   "aes",
		Short: "AES encryption and decryption",
		// Cobra only validates Args for runnable commands. ErrHelp preserves the
		// bare noun's help-before-I/O behavior while rejecting removed children.
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(*cobra.Command, []string) error {
			return nil
		},
		Long: `Perform AES encryption and decryption using a specified key.
AES-GCM is the authenticated default; select AES-CBC explicitly for compatibility.
The length of the key implicitly determines the AES variant used (128 or 256 bits).`,
	}
	encrypt := newEncryptCmd()
	decrypt := newDecryptCmd()
	aesCmd.AddCommand(encrypt, decrypt)
	for _, command := range []*cobra.Command{encrypt, decrypt} {
		lifecycle.Register(command, commandio.Behavior{
			Validate: func(cmd *cobra.Command) error {
				if err := validateAESFlagsBeforeIO(cmd); err != nil {
					return fmt.Errorf("validate AES flags: %w", err)
				}
				return nil
			},
			PrepareInput: func(cmd *cobra.Command) error {
				key, err := prepareAESKeyBeforeIO(cmd)
				if err != nil {
					return fmt.Errorf("validate AES key: %w", err)
				}
				cmd.SetContext(context.WithValue(cmd.Context(), aesPreparedKeyContextKey{}, key))
				return nil
			},
		})
	}
	lifecycle.RegisterCompletion(prepareAESCompletion)
	if err := help.RegisterGuides(aesCmd, aesGuideFiles); err != nil {
		panic(err)
	}
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
	if err := cmd.RegisterFlagCompletionFunc("cipher-mode", completeAESCipherModes); err != nil {
		panic(err)
	}
	cmd.Flags().String("aad", "", "additional authenticated data for GCM")
	registerAESNoFileFlagCompletion(cmd, "key")
	registerAESNoFileFlagCompletion(cmd, "aad")
}

func aesCipherModeNames() []string {
	return slices.Sorted(maps.Keys(aesCipherModes))
}

func aesCipherModeFromCommand(cmd *cobra.Command) (aesCipherMode, error) {
	name, err := cmd.Flags().GetString("cipher-mode")
	if err != nil {
		return "", fmt.Errorf("read cipher-mode flag: %w", err)
	}
	mode, ok := aesCipherModes[name]
	if !ok {
		return "", fmt.Errorf("%w %q (valid: %s)", ErrUnknownAESCipherMode, name, strings.Join(aesCipherModeNames(), ", "))
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
		return ErrAADCipherMode
	}
	if mode == aesCipherModeGCM && cmd.Flags().Changed("iv") {
		return ErrIVCipherMode
	}
	if err := validateAESStreamFlags(cmd, mode); err != nil {
		return err
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
		same, err := artifact.SamePath(keyfile, output)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("%w: --keyfile %q and --output %q", ErrAESKeyOutputCollision, keyfile, output)
		}
	}
	return nil
}

func getKey(cmd *cobra.Command) ([]byte, error) {
	if key, ok := cmd.Context().Value(aesPreparedKeyContextKey{}).([]byte); ok {
		return key, nil
	}
	return readAESKey(cmd)
}

type aesPreparedKeyContextKey struct{}

func prepareAESKeyBeforeIO(cmd *cobra.Command) ([]byte, error) {
	if !isAESOperation(cmd) {
		return nil, nil
	}
	key, err := readAESKey(cmd)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("%w: %w", crypter.ErrInvalidAESKeySize, aes.KeySizeError(len(key)))
	}
	return key, nil
}

func readAESKey(cmd *cobra.Command) ([]byte, error) {
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
	key, err := artifact.ReadFile(keyFilePath, artifact.MaxAESKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read keyfile %q: %w", keyFilePath, err)
	}
	return key, nil
}

func validateAESStreamFlags(cmd *cobra.Command, mode aesCipherMode) error {
	if rawFlag := cmd.Flags().Lookup("raw"); rawFlag != nil && rawFlag.Changed && mode == aesCipherModeCBC {
		return errRawCipherMode
	}
	chunkFlag := cmd.Flags().Lookup("chunk-size")
	if chunkFlag == nil {
		return nil
	}
	if chunkFlag.Changed && mode == aesCipherModeCBC {
		return errChunkCipherMode
	}
	raw, err := cmd.Flags().GetBool("raw")
	if err != nil {
		return fmt.Errorf("read raw flag: %w", err)
	}
	if chunkFlag.Changed && raw {
		return errRawChunkSize
	}
	value, err := cmd.Flags().GetString("chunk-size")
	if err != nil {
		return fmt.Errorf("read chunk-size flag: %w", err)
	}
	_, err = parseAESChunkSize(value)
	return err
}
