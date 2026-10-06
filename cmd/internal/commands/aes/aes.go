// Package aes constructs the AES encryption and decryption commands.
package aes

import (
	"bytes"
	"context"
	"crypto/aes"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/internal/crypter"
	"github.com/sosheskaz/swys/internal/symkey"
)

const (
	wireOpenPGP         = "openpgp"
	wireTink            = "tink"
	flagDerivedBits     = "derived-key-bits"
	keyFlagName         = "key"
	keyBase64FlagName   = "key-base64"
	flagHKDFHash        = "hkdf-hash"
	flagAAD             = "aad"
	commandDecrypt      = "decrypt"
	commandKeygen       = "keygen"
	commandKeyConvert   = "key-convert"
	keyFormatTinkBinary = "tink-binary"
	keyFormatTinkJSON   = "tink-json"
	keyFormatAuto       = "auto"
	hashSHA256          = "sha256"
	hashSHA512          = "sha512"
)

//go:embed guides
var aesGuideFiles embed.FS

type aesOperation struct {
	pgp        *crypter.OpenPGPReader
	input      io.Reader
	tinkReader io.Reader
	password   *crypter.OpenPGPPasswordEncryption
	primitive  tink.StreamingAEAD
	wire       string
	key        []byte
	aad        []byte
	chunk      uint32
}
type aesOperationContextKey struct{}

// NewCommand constructs the AES command family for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	aesCmd := &cobra.Command{
		Use: "aes", Short: "AES encryption and decryption",
		Long: "Encrypt and decrypt using standard OpenPGP or Tink streaming AES formats.",
	}
	help.ConfigureBranch(aesCmd)
	encrypt, decrypt := newEncryptCmd(), newDecryptCmd()
	keygen, convert, inspect := newAESKeygenCmd(), newAESKeyConvertCmd(), newAESKeyInspectCmd()
	aesCmd.AddCommand(encrypt, decrypt, keygen, convert, inspect)
	lifecycle.Register(keygen, commandio.Behavior{
		SupportsOutput: true, Validate: validateAESKeygenFlags, Prepare: prepareAESKeygenOutput,
	})
	lifecycle.Register(convert, commandio.Behavior{
		SupportsInput: true, SupportsOutput: true,
		Validate: validateAESKeyConvertFlags, Prepare: prepareAESKeyConversion,
	})
	lifecycle.Register(inspect, commandio.Behavior{
		SupportsInput: true, SupportsOutput: true,
		Validate: validateAESKeyInspectFlags, Prepare: prepareAESKeyInspection,
	})
	for _, command := range []*cobra.Command{encrypt, decrypt} {
		lifecycle.Register(command, commandio.Behavior{
			SupportsInput: true, SupportsOutput: true, Validate: validateAESFlagsBeforeIO, PrepareInput: prepareAESOperation,
		})
	}
	lifecycle.RegisterCompletion(prepareAESCompletion)
	if err := help.RegisterGuides(aesCmd, aesGuideFiles); err != nil {
		panic(err)
	}
	return aesCmd
}

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().String(keyBase64FlagName, "", "raw AES key as base64")
	cmd.Flags().StringP(keyFlagName, "k", "", "read the AES key or Tink keyset from this file")
	cmd.Flags().String("key-format", keyFormatAuto, "key file format (auto, raw, tink-json, tink-binary)")
	cmd.Flags().String("key-id", "", "decimal Tink key ID for OpenPGP")
	if err := cmd.MarkFlagFilename(keyFlagName); err != nil {
		panic(err)
	}
	addPasswordFlags(cmd)
	cmd.MarkFlagsMutuallyExclusive(keyBase64FlagName, keyFlagName, passwordFlagName, "password-command", "password-env")
	cmd.MarkFlagsOneRequired(keyBase64FlagName, keyFlagName, passwordFlagName, "password-command", "password-env")
	registerAESValueCompletion(cmd, "key-format", func() []string { return append([]string{keyFormatAuto}, keyFormatNames()...) })
}

func addAESWireFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("wire-format", "F", wireOpenPGP, "wire format (openpgp or tink)")
	cmd.Flags().String(flagAAD, "", "Tink additional authenticated data")
	cmd.Flags().String("chunk-size", "1MiB", "OpenPGP plaintext chunk or Tink ciphertext segment size")
	cmd.Flags().String(flagHKDFHash, hashSHA256, "Tink HKDF hash (sha256 or sha512)")
	cmd.Flags().Int(flagDerivedBits, 0, "Tink derived AES bits (default matches input key)")
	registerAESValueCompletion(cmd, "wire-format", func() []string { return []string{wireOpenPGP, wireTink} })
	registerAESNoFileFlagCompletion(cmd, "key-id")
	registerAESValueCompletion(cmd, flagDerivedBits, func() []string { return []string{"128", "256"} })
	registerAESNoFileFlagCompletion(cmd, keyBase64FlagName)
	registerAESNoFileFlagCompletion(cmd, flagAAD)
	registerAESNoFileFlagCompletion(cmd, "chunk-size")
	registerAESValueCompletion(cmd, flagHKDFHash, func() []string { return []string{hashSHA256, hashSHA512} })
}

func getAESString(cmd *cobra.Command, name string) (string, error) {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		return "", fmt.Errorf("read --%s: %w", name, err)
	}
	return value, nil
}

func getAESInt(cmd *cobra.Command, name string) (int, error) {
	value, err := cmd.Flags().GetInt(name)
	if err != nil {
		return 0, fmt.Errorf("read --%s: %w", name, err)
	}
	return value, nil
}

func operationKeyFormat(cmd *cobra.Command) (string, error) {
	return readerKeyFormatFlag(cmd, "key-format")
}

func validateAESFlagsBeforeIO(cmd *cobra.Command) error {
	if cmd.Flags().Changed(keyBase64FlagName) {
		if _, err := decodeAESKeyBase64(cmd); err != nil {
			return err
		}
	}
	wire, err := getAESString(cmd, "wire-format")
	if err != nil {
		return err
	}
	if wire != wireOpenPGP && wire != wireTink {
		return fmt.Errorf("%w %q", errAESWireFormat, wire)
	}
	if err := validateAESPasswordFlags(cmd); err != nil {
		return err
	}
	format, err := operationKeyFormat(cmd)
	if err != nil {
		return err
	}
	if err := validateAESFormatFlags(cmd, wire, format); err != nil {
		return err
	}
	if err := validateAESChunkFlag(cmd, wire); err != nil {
		return err
	}
	return validateAESKeyOutputCollision(cmd)
}

func validateAESFormatFlags(cmd *cobra.Command, wire, format string) error {
	if cmd.Flags().Changed(keyBase64FlagName) && cmd.Flags().Changed("key-format") && format != keyFormatRaw {
		return fmt.Errorf("%w: --key-base64 is always raw; --key-format applies to --key", errAESWireFlag)
	}
	if cmd.Flags().Changed("key-id") && (cmd.Flags().Changed(keyBase64FlagName) || format == keyFormatRaw) {
		return fmt.Errorf("%w: --key-id requires a Tink keyset", errAESWireFlag)
	}
	if wire == wireTink {
		if cmd.Flags().Changed("key-id") {
			return fmt.Errorf("%w: --key-id requires OpenPGP", errAESWireFlag)
		}
		return nil
	}
	for _, name := range []string{flagAAD, flagHKDFHash, flagDerivedBits} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("%w: --%s requires Tink", errAESWireFlag, name)
		}
	}
	if cmd.Name() == commandDecrypt && cmd.Flags().Changed("chunk-size") {
		return fmt.Errorf("%w: OpenPGP decryption reads --chunk-size from the packet", errAESWireFlag)
	}
	return nil
}

func validateAESChunkFlag(cmd *cobra.Command, wire string) error {
	value, err := getAESString(cmd, "chunk-size")
	if err != nil {
		return err
	}
	chunk, err := parseAESChunkSize(value)
	if err != nil {
		return err
	}
	if wire == wireOpenPGP && (chunk > crypter.MaxOpenPGPChunkSize || chunk&(chunk-1) != 0) {
		return fmt.Errorf("%w: OpenPGP chunk size must be a power of two from 64B through 4MiB", errAESWireFlag)
	}
	return nil
}

func validateAESKeyOutputCollision(cmd *cobra.Command) error {
	keyfile, err := getAESString(cmd, keyFlagName)
	if err != nil {
		return err
	}
	output, err := getAESString(cmd, "output")
	if err != nil {
		return err
	}
	output = commandio.NormalizeMainStreamPath(output)
	if keyfile == "" || output == "" {
		return nil
	}
	same, err := artifact.SamePath(keyfile, output)
	if err != nil {
		return err
	}
	if same {
		return fmt.Errorf("%w: --key %q and --output %q", ErrAESKeyOutputCollision, keyfile, output)
	}
	return nil
}

func prepareAESOperation(cmd *cobra.Command) error {
	wire, err := getAESString(cmd, "wire-format")
	if err != nil {
		return err
	}
	chunkText, err := getAESString(cmd, "chunk-size")
	if err != nil {
		return err
	}
	chunk, err := parseAESChunkSize(chunkText)
	if err != nil {
		return err
	}
	aadText, err := getAESString(cmd, flagAAD)
	if err != nil {
		return err
	}
	op := &aesOperation{wire: wire, chunk: chunk, aad: []byte(aadText)}
	if passwordSelected(cmd) {
		if err := prepareAESPassword(cmd, op); err != nil {
			return err
		}
		cmd.SetContext(context.WithValue(cmd.Context(), aesOperationContextKey{}, op))
		return nil
	}
	key, handle, err := readAESOperationKey(cmd)
	if err != nil {
		return err
	}
	if err := prepareAESPrimitive(cmd, op, key, handle); err != nil {
		return err
	}
	if cmd.Name() == commandDecrypt {
		if err := prepareAESDecryptInput(cmd, op); err != nil {
			return err
		}
	}
	cmd.SetContext(context.WithValue(cmd.Context(), aesOperationContextKey{}, op))
	return nil
}

func readAESOperationKey(cmd *cobra.Command) ([]byte, *keyset.Handle, error) {
	if cmd.Flags().Changed(keyBase64FlagName) {
		key, err := decodeAESKeyBase64(cmd)
		if err != nil {
			return nil, nil, err
		}
		return key, nil, nil
	}
	path, err := getAESString(cmd, keyFlagName)
	if err != nil {
		return nil, nil, err
	}
	format, err := operationKeyFormat(cmd)
	if err != nil {
		return nil, nil, err
	}
	data, err := artifact.ReadFile(path, aesKeyInputLimit(format))
	if err != nil {
		return nil, nil, fmt.Errorf("read AES keyfile %q: %w", path, err)
	}
	format = detectAESKeyFormat(data, format)
	if format == keyFormatRaw {
		return data, nil, nil
	}
	handle, err := symkey.Read(data, format)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid AES keyfile (%s): %w", format, err)
	}
	return nil, handle, nil
}

func decodeAESKeyBase64(cmd *cobra.Command) ([]byte, error) {
	value, err := getAESString(cmd, keyBase64FlagName)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("decode --%s: %w", keyBase64FlagName, err)
	}
	return key, nil
}

func prepareAESPrimitive(cmd *cobra.Command, op *aesOperation, key []byte, handle *keyset.Handle) error {
	if handle == nil && cmd.Flags().Changed("key-id") {
		return fmt.Errorf("%w: --key-id requires a Tink keyset", errAESWireFlag)
	}
	if handle != nil {
		if op.wire == wireTink {
			return prepareTinkKeyset(cmd, op, handle)
		}
		var err error
		key, err = selectOpenPGPKeysetKey(cmd, handle)
		if err != nil {
			return err
		}
	}
	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("%w: %w", crypter.ErrInvalidAESKeySize, aes.KeySizeError(len(key)))
	}
	op.key = key
	if op.wire == wireTink {
		return prepareRawTink(cmd, op)
	}
	return nil
}

func selectOpenPGPKeysetKey(cmd *cobra.Command, handle *keyset.Handle) ([]byte, error) {
	if !cmd.Flags().Changed("key-id") {
		info, err := symkey.Inspect(handle)
		if err != nil {
			return nil, err
		}
		return symkey.Raw(handle, &info.PrimaryKeyID)
	}
	idText, err := getAESString(cmd, "key-id")
	if err != nil {
		return nil, err
	}
	id, err := strconv.ParseUint(idText, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid decimal key ID %q: %w", idText, err)
	}
	selected := uint32(id)
	return symkey.Raw(handle, &selected)
}

func prepareTinkKeyset(cmd *cobra.Command, op *aesOperation, handle *keyset.Handle) error {
	params, err := symkey.PrimaryParameters(handle)
	if err != nil {
		return err
	}
	if err := checkTinkKeysetFlags(cmd, params); err != nil {
		return err
	}
	op.primitive, err = streamingaead.New(handle)
	if err != nil {
		return fmt.Errorf("prepare Tink keyset: %w", err)
	}
	return nil
}

func prepareRawTink(cmd *cobra.Command, op *aesOperation) error {
	params, err := tinkRawParams(cmd, op.chunk, len(op.key)*8)
	if err != nil {
		return err
	}
	hash := "SHA256"
	if params.Hash == commonpb.HashType_SHA512 {
		hash = "SHA512"
	}
	op.primitive, err = subtle.NewAESGCMHKDF(op.key, hash, params.DerivedKeyBits/8, int(params.SegmentSize), 0)
	if err != nil {
		return fmt.Errorf("prepare Tink key: %w", err)
	}
	return nil
}

func prepareAESDecryptInput(cmd *cobra.Command, op *aesOperation) error {
	input, err := commandio.CommandInput(cmd, cmd.Flags().Args())
	if err != nil {
		return err
	}
	op.input = input
	if op.wire == wireOpenPGP {
		op.pgp, err = crypter.PrepareOpenPGP(op.key, input)
		return err
	}
	reader, err := op.primitive.NewDecryptingReader(input, op.aad)
	if err != nil {
		return fmt.Errorf("read Tink header: %w", err)
	}
	// Keysets match a key on the first read, which also authenticates the first
	// segment, so perform it before output is opened and replay its bytes.
	first := make([]byte, 512)
	n, err := reader.Read(first)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decrypt Tink stream: %w", err)
	}
	op.tinkReader = io.MultiReader(bytes.NewReader(first[:n]), reader)
	return nil
}

func tinkRawParams(cmd *cobra.Command, chunk uint32, bits int) (symkey.Parameters, error) {
	hashName, err := getAESString(cmd, flagHKDFHash)
	if err != nil {
		return symkey.Parameters{}, err
	}
	hash, err := parseTinkHash(hashName)
	if err != nil {
		return symkey.Parameters{}, err
	}
	derived, err := getAESInt(cmd, flagDerivedBits)
	if err != nil {
		return symkey.Parameters{}, err
	}
	if derived == 0 {
		derived = bits
	}
	if err := validateTinkDerived(derived, bits, chunk); err != nil {
		return symkey.Parameters{}, err
	}
	return symkey.Parameters{SegmentSize: chunk, Hash: hash, DerivedKeyBits: derived}, nil
}

func checkTinkKeysetFlags(cmd *cobra.Command, params symkey.Parameters) error {
	if cmd.Flags().Changed("chunk-size") {
		text, err := getAESString(cmd, "chunk-size")
		if err != nil {
			return err
		}
		size, err := parseAESChunkSize(text)
		if err != nil {
			return err
		}
		if size != params.SegmentSize {
			return fmt.Errorf("%w: --chunk-size conflicts with Tink keyset", errAESWireFlag)
		}
	}
	if cmd.Flags().Changed(flagHKDFHash) {
		text, err := getAESString(cmd, flagHKDFHash)
		if err != nil {
			return err
		}
		hash, err := parseTinkHash(text)
		if err != nil {
			return err
		}
		if hash != params.Hash {
			return fmt.Errorf("%w: --hkdf-hash conflicts with Tink keyset", errAESWireFlag)
		}
	}
	if cmd.Flags().Changed(flagDerivedBits) {
		bits, err := getAESInt(cmd, flagDerivedBits)
		if err != nil {
			return err
		}
		if bits != params.DerivedKeyBits {
			return fmt.Errorf("%w: --derived-key-bits conflicts with Tink keyset", errAESWireFlag)
		}
	}
	return nil
}
