package crypter

import "testing"

func TestAESConstructorsReject192BitKeys(t *testing.T) {
	t.Parallel()

	key := make([]byte, 24)
	if crypter, err := NewAESCrypter(key); err == nil {
		t.Fatalf("NewAESCrypter(24-byte key) = %#v, nil; want rejection", crypter)
	}
	if crypter, err := NewAESGCMCrypter(key); err == nil {
		t.Fatalf("NewAESGCMCrypter(24-byte key) = %#v, nil; want rejection", crypter)
	}
}
