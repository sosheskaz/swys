// Package symkey handles standard cleartext Tink AES-GCM-HKDF keysets.
package symkey

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	aespb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"google.golang.org/protobuf/proto"
)

const (
	// TypeURL identifies Tink's AES-GCM-HKDF streaming key type.
	TypeURL = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"
	// MaxSegmentSize caps a parsed keyset's declared ciphertext segment size.
	MaxSegmentSize uint32 = 64 << 20
)

var (
	errFormat    = errors.New("unsupported key format")
	errHandle    = errors.New("cannot create Tink keyset handle")
	errType      = errors.New("unsupported Tink key type")
	errVersion   = errors.New("unsupported AES key version")
	errKeySize   = errors.New("AES key must be 128 or 256 bits")
	errDerived   = errors.New("derived AES key must be 128 or 256 bits and no larger than input key")
	errHash      = errors.New("unsupported HKDF hash")
	errSegment   = errors.New("invalid Tink ciphertext segment size")
	errAmbiguous = errors.New("multiple Tink keys require --key-id")
	errDisabled  = errors.New("selected Tink key is not enabled")
	errMissing   = errors.New("selected Tink key does not exist")
)

// Parameters are the Tink AES-GCM-HKDF streaming parameters.
type Parameters struct {
	SegmentSize    uint32
	Hash           commonpb.HashType
	DerivedKeyBits int
}

// KeyInfo contains only non-secret metadata about a keyset entry.
type KeyInfo struct {
	Status         string `json:"status"`
	Hash           string `json:"hkdf_hash"`
	KeyBits        int    `json:"key_bits"`
	DerivedKeyBits int    `json:"derived_key_bits"`
	ID             uint32 `json:"id"`
	SegmentSize    uint32 `json:"ciphertext_segment_size"`
}

// Info contains only non-secret keyset metadata.
type Info struct {
	Keys         []KeyInfo `json:"keys"`
	PrimaryKeyID uint32    `json:"primary_key_id"`
}

// New creates one enabled primary AES-GCM-HKDF streaming key from raw material.
func New(raw []byte, params Parameters) (*keyset.Handle, error) {
	if err := validateParams(raw, params); err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	encoded, err := proto.Marshal(&aespb.AesGcmHkdfStreamingKey{
		Version: 0,
		Params: &aespb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: params.SegmentSize, HkdfHashType: params.Hash,
			DerivedKeySize: uint32(params.DerivedKeyBits / 8), //nolint:gosec // validated as 128 or 256 bits above
		},
		KeyValue: bytes.Clone(raw),
	})
	if err != nil {
		return nil, fmt.Errorf("encode Tink AES key: %w", err)
	}
	material := &tinkpb.Keyset{PrimaryKeyId: id, Key: []*tinkpb.Keyset_Key{{
		KeyId: id, Status: tinkpb.KeyStatusType_ENABLED, OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		KeyData: &tinkpb.KeyData{TypeUrl: TypeURL, KeyMaterialType: tinkpb.KeyData_SYMMETRIC, Value: encoded},
	}}}
	return validate(material)
}

func randomID() (uint32, error) {
	var data [4]byte
	for {
		if _, err := rand.Read(data[:]); err != nil {
			return 0, fmt.Errorf("generate Tink key ID: %w", err)
		}
		if id := binary.BigEndian.Uint32(data[:]); id != 0 {
			return id, nil
		}
	}
}

// Read parses a bounded cleartext Tink keyset in a native format.
// Callers must cap the serialized input before calling Read.
func Read(data []byte, format string) (*keyset.Handle, error) {
	var reader keyset.Reader
	switch format {
	case "tink-json":
		reader = keyset.NewJSONReader(bytes.NewReader(data))
	case "tink-binary":
		reader = keyset.NewBinaryReader(bytes.NewReader(data))
	default:
		return nil, fmt.Errorf("%w %q", errFormat, format)
	}
	handle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("read Tink keyset: %w", err)
	}
	return validate(insecurecleartextkeyset.KeysetMaterial(handle))
}

func validate(material *tinkpb.Keyset) (*keyset.Handle, error) {
	if err := keyset.Validate(material); err != nil {
		return nil, fmt.Errorf("validate Tink keyset: %w", err)
	}
	for _, entry := range material.Key {
		if _, err := parseKey(entry); err != nil {
			return nil, fmt.Errorf("validate Tink key %d: %w", entry.GetKeyId(), err)
		}
	}
	encoded, err := proto.Marshal(material)
	if err != nil {
		return nil, fmt.Errorf("encode Tink keyset: %w", err)
	}
	handle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(encoded)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errHandle, err)
	}
	if _, err := streamingaead.New(handle); err != nil {
		return nil, fmt.Errorf("validate Tink streaming primitive: %w", err)
	}
	return handle, nil
}

func parseKey(entry *tinkpb.Keyset_Key) (*aespb.AesGcmHkdfStreamingKey, error) {
	if entry.GetKeyData().GetTypeUrl() != TypeURL || entry.GetKeyData().GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
		return nil, errType
	}
	key := new(aespb.AesGcmHkdfStreamingKey)
	if err := proto.Unmarshal(entry.GetKeyData().GetValue(), key); err != nil {
		return nil, fmt.Errorf("decode AES key: %w", err)
	}
	if key.GetVersion() != 0 {
		return nil, fmt.Errorf("%w %d", errVersion, key.GetVersion())
	}
	params := Parameters{
		SegmentSize:    key.GetParams().GetCiphertextSegmentSize(),
		Hash:           key.GetParams().GetHkdfHashType(),
		DerivedKeyBits: int(key.GetParams().GetDerivedKeySize()) * 8,
	}
	if err := validateParams(key.GetKeyValue(), params); err != nil {
		return nil, err
	}
	return key, nil
}

func validateParams(raw []byte, params Parameters) error {
	if len(raw) != 16 && len(raw) != 32 {
		return fmt.Errorf("%w, got %d", errKeySize, len(raw)*8)
	}
	if params.DerivedKeyBits != 128 && params.DerivedKeyBits != 256 || params.DerivedKeyBits > len(raw)*8 {
		return errDerived
	}
	if params.Hash != commonpb.HashType_SHA256 && params.Hash != commonpb.HashType_SHA512 {
		return fmt.Errorf("%w %s", errHash, params.Hash)
	}
	if params.SegmentSize < 64 || params.SegmentSize > MaxSegmentSize ||
		uint64(params.SegmentSize) <= uint64(params.DerivedKeyBits/8+24) { //nolint:gosec // derived size is validated above

		return fmt.Errorf("%w: must be 64 through %d bytes and larger than derived key size plus 24", errSegment, MaxSegmentSize)
	}
	return nil
}

// Write serializes an unchanged keyset through Tink's native writer.
func Write(handle *keyset.Handle, format string) ([]byte, error) {
	var output bytes.Buffer
	var writer keyset.Writer
	switch format {
	case "tink-json":
		writer = keyset.NewJSONWriter(&output)
	case "tink-binary":
		writer = keyset.NewBinaryWriter(&output)
	default:
		return nil, fmt.Errorf("%w %q", errFormat, format)
	}
	if err := insecurecleartextkeyset.Write(handle, writer); err != nil {
		return nil, fmt.Errorf("write Tink keyset: %w", err)
	}
	return output.Bytes(), nil
}

// Raw selects one enabled key and returns a copy of its material.
// A key ID is required whenever the keyset contains multiple entries.
func Raw(handle *keyset.Handle, id *uint32) ([]byte, error) {
	material := insecurecleartextkeyset.KeysetMaterial(handle)
	if id == nil && len(material.Key) != 1 {
		return nil, errAmbiguous
	}
	for _, entry := range material.Key {
		if id != nil && entry.KeyId != *id {
			continue
		}
		if entry.Status != tinkpb.KeyStatusType_ENABLED {
			return nil, fmt.Errorf("%w: %d", errDisabled, entry.KeyId)
		}
		key, err := parseKey(entry)
		if err != nil {
			return nil, err
		}
		return bytes.Clone(key.KeyValue), nil
	}
	return nil, errMissing
}

// PrimaryParameters returns the enabled primary key's streaming parameters.
func PrimaryParameters(handle *keyset.Handle) (Parameters, error) {
	material := insecurecleartextkeyset.KeysetMaterial(handle)
	for _, entry := range material.Key {
		if entry.KeyId != material.PrimaryKeyId {
			continue
		}
		if entry.Status != tinkpb.KeyStatusType_ENABLED {
			return Parameters{}, errDisabled
		}
		key, err := parseKey(entry)
		if err != nil {
			return Parameters{}, err
		}
		return Parameters{
			SegmentSize: key.Params.CiphertextSegmentSize,
			Hash:        key.Params.HkdfHashType, DerivedKeyBits: int(key.Params.DerivedKeySize) * 8,
		}, nil
	}
	return Parameters{}, errMissing
}

// Inspect returns keyset metadata without key bytes.
func Inspect(handle *keyset.Handle) (Info, error) {
	material := insecurecleartextkeyset.KeysetMaterial(handle)
	info := Info{PrimaryKeyID: material.PrimaryKeyId}
	for _, entry := range material.Key {
		key, err := parseKey(entry)
		if err != nil {
			return Info{}, err
		}
		info.Keys = append(info.Keys, KeyInfo{
			ID: entry.KeyId, Status: entry.Status.String(), KeyBits: len(key.KeyValue) * 8,
			DerivedKeyBits: int(key.Params.DerivedKeySize) * 8,
			SegmentSize:    key.Params.CiphertextSegmentSize, Hash: key.Params.HkdfHashType.String(),
		})
	}
	return info, nil
}
