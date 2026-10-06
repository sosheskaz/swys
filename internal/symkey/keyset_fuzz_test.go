package symkey_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	"google.golang.org/protobuf/proto"

	"github.com/sosheskaz/swys/internal/symkey"
)

func FuzzReadKeyset(f *testing.F) {
	handle, err := symkey.New(bytes.Repeat([]byte{0x42}, 16), symkey.Parameters{
		SegmentSize: 64, Hash: commonpb.HashType_SHA256, DerivedKeyBits: 128,
	})
	if err != nil {
		f.Fatal(err)
	}
	for selector, format := range []string{"tink-json", "tink-binary"} {
		encoded, writeErr := symkey.Write(handle, format)
		if writeErr != nil {
			f.Fatal(writeErr)
		}
		f.Add(uint8(selector), encoded)
		f.Add(uint8(selector), encoded[:len(encoded)/2])
	}
	f.Add(uint8(0), []byte("{"))
	f.Add(uint8(1), []byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, selector uint8, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		formats := [...]string{"tink-json", "tink-binary"}
		format := formats[selector%uint8(len(formats))]
		parsed, readErr := symkey.Read(data, format)
		if readErr != nil {
			return
		}
		written, writeErr := symkey.Write(parsed, format)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		roundtrip, readErr := symkey.Read(written, format)
		if readErr != nil {
			t.Fatal(readErr)
		}
		before := insecurecleartextkeyset.KeysetMaterial(parsed)
		after := insecurecleartextkeyset.KeysetMaterial(roundtrip)
		if !proto.Equal(before, after) {
			t.Fatal("accepted keyset changed key material or metadata after serialization")
		}
	})
}
