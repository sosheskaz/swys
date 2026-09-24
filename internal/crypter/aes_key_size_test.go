package crypter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESConstructorsReject192BitKeys(t *testing.T) {
	t.Parallel()

	key := make([]byte, 24)
	cbc, cbcErr := NewAESCrypter(key)
	require.Error(t, cbcErr, "NewAESCrypter(24-byte key) returned %#v", cbc)
	gcm, gcmErr := NewAESGCMCrypter(key)
	assert.Error(t, gcmErr, "NewAESGCMCrypter(24-byte key) returned %#v", gcm)
}
