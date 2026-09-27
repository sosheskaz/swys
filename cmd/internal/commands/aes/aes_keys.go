package aes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/symkey"
)

const (
	keyFormatRaw   = "raw"
	inspectionJSON = "json"
)

var (
	errAESKeyFormat        = errors.New("unknown AES key format")
	errAESParameter        = errors.New("invalid Tink key parameter")
	errAESKeyID            = errors.New("invalid key ID selection")
	errAESKeySize          = errors.New("AES key must be 128 or 256 bits")
	errAESInspectionFormat = errors.New("unsupported inspection format")
)

func keyFormatNames() []string { return []string{keyFormatRaw, "tink-json", "tink-binary"} }

func keyFormatFlag(cmd *cobra.Command, flag string) (string, error) {
	value, err := cmd.Flags().GetString(flag)
	if err != nil {
		return "", fmt.Errorf("read %s flag: %w", flag, err)
	}
	for _, name := range keyFormatNames() {
		if value == name {
			return value, nil
		}
	}
	return "", fmt.Errorf("%w %q", errAESKeyFormat, value)
}

func addTinkParameterFlags(cmd *cobra.Command) {
	cmd.Flags().String("chunk-size", "1MiB", "Tink ciphertext segment size (64B through 64MiB)")
	cmd.Flags().String("hkdf-hash", "sha256", "Tink HKDF hash (sha256 or sha512)")
	cmd.Flags().Int("derived-key-bits", 0, "Tink derived AES key bits (128 or 256; default matches input key)")
	commandio.RegisterFlagCompletion(cmd, "hkdf-hash", func() []string { return []string{"sha256", "sha512"} })
	commandio.RegisterFlagCompletion(cmd, "derived-key-bits", func() []string { return []string{"128", "256"} })
}

func tinkParamsFromCommand(cmd *cobra.Command, target string, bits int) (symkey.Parameters, error) {
	if target == keyFormatRaw {
		for _, name := range []string{"chunk-size", "hkdf-hash", "derived-key-bits"} {
			if cmd.Flags().Changed(name) {
				return symkey.Parameters{}, fmt.Errorf("%w: --%s requires a Tink key output", errAESParameter, name)
			}
		}
		return symkey.Parameters{}, nil
	}
	chunk, err := cmd.Flags().GetString("chunk-size")
	if err != nil {
		return symkey.Parameters{}, fmt.Errorf("read chunk-size flag: %w", err)
	}
	segment, err := parseAESChunkSize(chunk)
	if err != nil {
		return symkey.Parameters{}, err
	}
	if segment < 64 || segment > symkey.MaxSegmentSize {
		return symkey.Parameters{}, fmt.Errorf("%w: chunk-size must be 64B through 64MiB", errAESParameter)
	}
	hashName, err := cmd.Flags().GetString("hkdf-hash")
	if err != nil {
		return symkey.Parameters{}, fmt.Errorf("read hkdf-hash flag: %w", err)
	}
	hash, err := parseTinkHash(hashName)
	if err != nil {
		return symkey.Parameters{}, err
	}
	derived, err := cmd.Flags().GetInt("derived-key-bits")
	if err != nil {
		return symkey.Parameters{}, fmt.Errorf("read derived-key-bits flag: %w", err)
	}
	if derived == 0 {
		derived = bits
	}
	if err := validateTinkDerived(derived, bits, segment); err != nil {
		return symkey.Parameters{}, err
	}
	return symkey.Parameters{SegmentSize: segment, Hash: hash, DerivedKeyBits: derived}, nil
}

func validateTinkDerived(derived, bits int, segment uint32) error {
	if derived != 128 && derived != 256 || derived > bits || uint64(segment) <= uint64(derived/8+24) { //nolint:gosec // derived is checked before conversion
		return fmt.Errorf("%w: derived key size or segment size", errAESParameter)
	}
	return nil
}

func parseTinkHash(name string) (commonpb.HashType, error) {
	switch name {
	case "sha256":
		return commonpb.HashType_SHA256, nil
	case "sha512":
		return commonpb.HashType_SHA512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported HKDF hash %q", errAESParameter, name)
	}
}

func prepareAESKeygenOutput(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
	bits, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return nil, fmt.Errorf("read bits flag: %w", err)
	}
	format, err := keyFormatFlag(cmd, "key-format")
	if err != nil {
		return nil, err
	}
	var raw bytes.Buffer
	if err := generateAESKey(bits, &raw); err != nil {
		return nil, err
	}
	if format == keyFormatRaw {
		return raw.Bytes(), nil
	}
	params, err := tinkParamsFromCommand(cmd, format, bits)
	if err != nil {
		return nil, err
	}
	handle, err := symkey.New(raw.Bytes(), params)
	if err != nil {
		return nil, err
	}
	return symkey.Write(handle, format)
}

func newAESKeyConvertCmd() *cobra.Command {
	cmd := commandio.SensitiveBinaryOutputCommand(&cobra.Command{
		Use: "key-convert", Short: "Convert raw AES keys and cleartext Tink keysets", Args: cobra.NoArgs,
		RunE: writePreparedAESKey,
	}, true)
	cmd.Flags().String("from", "", "source key format (raw, tink-json, tink-binary)")
	cmd.Flags().String("to", "", "target key format (raw, tink-json, tink-binary)")
	cmd.Flags().String("key-id", "", "decimal Tink key ID for raw export")
	addTinkParameterFlags(cmd)
	for _, name := range []string{"from", "to"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
		commandio.RegisterFlagCompletion(cmd, name, keyFormatNames)
	}
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func validateAESKeyConvertFlags(cmd *cobra.Command) error {
	from, err := keyFormatFlag(cmd, "from")
	if err != nil {
		return err
	}
	to, err := keyFormatFlag(cmd, "to")
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("key-id") && (from == keyFormatRaw || to != keyFormatRaw) {
		return fmt.Errorf("%w: --key-id requires Tink source and raw target", errAESKeyID)
	}
	if from != keyFormatRaw {
		for _, name := range []string{"chunk-size", "hkdf-hash", "derived-key-bits"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("%w: --%s applies only to raw key imports", errAESParameter, name)
			}
		}
	}
	if from == keyFormatRaw {
		_, err = tinkParamsFromCommand(cmd, to, 256)
		if err != nil {
			return err
		}
	}
	return nil
}

func prepareAESKeyConversion(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	from, err := keyFormatFlag(cmd, "from")
	if err != nil {
		return nil, err
	}
	to, err := keyFormatFlag(cmd, "to")
	if err != nil {
		return nil, err
	}
	limit := artifact.MaxKeyBytes
	if from == keyFormatRaw {
		limit = artifact.MaxAESKeyBytes
	}
	data, err := artifact.Read(input, limit)
	if err != nil {
		return nil, fmt.Errorf("read AES key: %w", err)
	}
	if from == keyFormatRaw {
		return convertRawAESKey(cmd, data, to)
	}
	handle, err := symkey.Read(data, from)
	if err != nil {
		return nil, err
	}
	if to != keyFormatRaw {
		return symkey.Write(handle, to)
	}
	var selected *uint32
	if cmd.Flags().Changed("key-id") {
		idText, err := cmd.Flags().GetString("key-id")
		if err != nil {
			return nil, fmt.Errorf("read key-id flag: %w", err)
		}
		id, err := strconv.ParseUint(idText, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid decimal key ID %q: %w", idText, err)
		}
		value := uint32(id)
		selected = &value
	}
	return symkey.Raw(handle, selected)
}

func convertRawAESKey(cmd *cobra.Command, data []byte, to string) ([]byte, error) {
	if len(data) != 16 && len(data) != 32 {
		return nil, errAESKeySize
	}
	if to == keyFormatRaw {
		return data, nil
	}
	params, err := tinkParamsFromCommand(cmd, to, len(data)*8)
	if err != nil {
		return nil, err
	}
	handle, err := symkey.New(data, params)
	if err != nil {
		return nil, err
	}
	return symkey.Write(handle, to)
}

func writePreparedAESKey(cmd *cobra.Command, _ []string) error {
	prepared, output, err := commandio.TakePrepared(cmd)
	if err != nil {
		return err
	}
	n, err := output.Write(prepared)
	if err != nil {
		return fmt.Errorf("write AES key output: %w", err)
	}
	if n != len(prepared) {
		return fmt.Errorf("write AES key output: %w", io.ErrShortWrite)
	}
	return nil
}

func newAESKeyInspectCmd() *cobra.Command {
	cmd := commandio.EncodedInputCommand(commandio.StructuredOutputCommand(&cobra.Command{
		Use: "key-inspect", Short: "Inspect AES key metadata without revealing key material", Args: cobra.NoArgs,
		RunE: writePreparedAESKey,
	}, func() []string { return []string{"text", inspectionJSON} }))
	cmd.Flags().String("key-format", keyFormatRaw, "key format (raw, tink-json, tink-binary)")
	commandio.RegisterFlagCompletion(cmd, "key-format", keyFormatNames)
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func validateAESKeyInspectFlags(cmd *cobra.Command) error {
	if _, err := keyFormatFlag(cmd, "key-format"); err != nil {
		return err
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return fmt.Errorf("read format flag: %w", err)
	}
	if format != "text" && format != inspectionJSON {
		return fmt.Errorf("%w %q", errAESInspectionFormat, format)
	}
	return nil
}

func prepareAESKeyInspection(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	keyFormat, err := keyFormatFlag(cmd, "key-format")
	if err != nil {
		return nil, err
	}
	limit := artifact.MaxKeyBytes
	if keyFormat == keyFormatRaw {
		limit = artifact.MaxAESKeyBytes
	}
	data, err := artifact.Read(input, limit)
	if err != nil {
		return nil, fmt.Errorf("read AES key: %w", err)
	}
	var info symkey.Info
	if keyFormat == keyFormatRaw {
		if len(data) != 16 && len(data) != 32 {
			return nil, errAESKeySize
		}
		info.Keys = []symkey.KeyInfo{{KeyBits: len(data) * 8}}
	} else {
		handle, err := symkey.Read(data, keyFormat)
		if err != nil {
			return nil, err
		}
		info, err = symkey.Inspect(handle)
		if err != nil {
			return nil, err
		}
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return nil, fmt.Errorf("read format flag: %w", err)
	}
	if format == inspectionJSON {
		encoded, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("format AES key metadata: %w", err)
		}
		return encoded, nil
	}
	var output strings.Builder
	if keyFormat == keyFormatRaw {
		fmt.Fprintf(&output, "Raw AES key: %d bits\n", info.Keys[0].KeyBits)
	} else {
		fmt.Fprintf(&output, "Primary key ID: %d\n", info.PrimaryKeyID)
		for _, key := range info.Keys {
			fmt.Fprintf(&output, "Key %d: %s, AES-%d, derived AES-%d, %s, %d-byte segments\n",
				key.ID, key.Status, key.KeyBits, key.DerivedKeyBits, key.Hash, key.SegmentSize)
		}
	}
	return []byte(output.String()), nil
}
