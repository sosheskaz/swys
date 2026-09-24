//go:build darwin

package securefile

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestOpenOrCreateOwnerOnlyRejectsExistingDarwinACL(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	addDarwinACL(t, path, "everyone allow read")

	_, err := OpenOrCreateOwnerOnly(path)
	require.ErrorIs(t, err, ErrNotOwnerOnly)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
}

func TestOpenOrCreateOwnerOnlyRejectsCurrentUserDarwinACL(t *testing.T) {
	t.Parallel()

	current, err := user.Current()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "private.key")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	addDarwinACL(t, path, current.Username+" allow read")

	_, err = OpenOrCreateOwnerOnly(path)
	assert.ErrorIs(t, err, ErrNotOwnerOnly)
}

func TestOpenOrCreateOwnerOnlySuppressesInheritedDarwinACL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	addDarwinACL(t, dir, "everyone allow read,file_inherit")
	path := filepath.Join(dir, "private.key")
	file, err := OpenOrCreateOwnerOnly(path)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	assertNoDarwinACL(t, path)
}

func TestDarwinReturnedCommonAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		buffer []byte
	}{
		{name: "missing header", buffer: nil},
		{name: "reported size too small", buffer: darwinAttributeResponse(darwinAttributeResponseHeader-1, unix.ATTR_CMN_RETURNED_ATTRS)},
		{name: "reported size exceeds buffer", buffer: darwinAttributeResponse(darwinAttributeResponseHeader+1, unix.ATTR_CMN_RETURNED_ATTRS)},
		{name: "missing returned attributes", buffer: darwinAttributeResponse(darwinAttributeResponseHeader, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := darwinReturnedCommonAttributes(tt.buffer)
			assert.Error(t, err, "malformed response")
		})
	}

	buffer := darwinAttributeResponse(
		darwinAttributeResponseHeader,
		unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY,
	)
	common, err := darwinReturnedCommonAttributes(buffer)
	require.NoError(t, err)
	assert.NotZero(t, common&unix.ATTR_CMN_EXTENDED_SECURITY, "common attributes = %#x", common)
}

func FuzzDarwinReturnedCommonAttributes(f *testing.F) {
	f.Add(darwinAttributeResponse(darwinAttributeResponseHeader, unix.ATTR_CMN_RETURNED_ATTRS))
	f.Add(darwinAttributeResponse(
		darwinAttributeResponseHeader,
		unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY,
	))
	f.Add(darwinAttributeResponse(darwinAttributeResponseHeader-1, unix.ATTR_CMN_RETURNED_ATTRS))
	f.Add(darwinAttributeResponse(darwinAttributeResponseHeader+1, unix.ATTR_CMN_RETURNED_ATTRS))
	f.Add(darwinAttributeResponse(darwinAttributeResponseHeader, 0))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, buffer []byte) {
		if len(buffer) > darwinMaxAttributeResponse {
			t.Skip()
		}
		// Re-derive acceptance from the buffer bytes so every bound in the
		// parser is pinned rather than merely exercised.
		common, err := darwinReturnedCommonAttributes(buffer)
		valid := len(buffer) >= darwinAttributeResponseHeader
		var want uint32
		if valid {
			reported := binary.NativeEndian.Uint32(buffer[0:4])
			want = binary.NativeEndian.Uint32(buffer[4:8])
			valid = reported >= darwinAttributeResponseHeader &&
				uint64(reported) <= uint64(len(buffer)) &&
				want&unix.ATTR_CMN_RETURNED_ATTRS != 0
		}
		if (err == nil) != valid {
			t.Fatalf("attribute response acceptance = %v, want valid %t", err, valid)
		}
		if valid && common != want {
			t.Fatalf("common attributes = %#x, want %#x", common, want)
		}
		if !valid && !errors.Is(err, errMalformedDarwinAttributeResponse) {
			t.Fatalf("error = %v, want malformed response", err)
		}
		if !valid && common != 0 {
			t.Fatalf("rejected attribute response returned %#x, want 0", common)
		}
	})
}

func darwinAttributeResponse(reportedSize int, common uint32) []byte {
	buffer := make([]byte, darwinAttributeResponseHeader)
	binary.NativeEndian.PutUint32(buffer[0:4], uint32(reportedSize))
	binary.NativeEndian.PutUint32(buffer[4:8], common)
	return buffer
}

func addDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "/bin/chmod", "+a", entry, path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("add ACL: %v: %s", err, output)
	}
}

func assertNoDarwinACL(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, file.Close())
	}()
	hasACL, err := hasDarwinExtendedACL(file)
	require.NoError(t, err)
	assert.False(t, hasACL, "new file inherited an extended ACL")
}
