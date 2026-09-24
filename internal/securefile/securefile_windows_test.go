//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestOwnerOnlyWindowsSecurityDescriptor(t *testing.T) {
	t.Parallel()

	descriptor, err := ownerOnlyWindowsSecurityDescriptor()
	require.NoError(t, err)
	assert.NoError(t, validateOwnerOnlyWindowsSecurityDescriptor(descriptor))
}

func TestValidateOwnerOnlyWindowsSecurityDescriptorRejectsUnsafeDACLs(t *testing.T) {
	t.Parallel()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	tests := []struct {
		name string
		sddl string
	}{
		{name: "missing owner", sddl: "D:P(A;;GA;;;" + user.User.Sid.String() + ")"},
		{name: "another owner", sddl: "O:WDD:P(A;;GA;;;" + user.User.Sid.String() + ")"},
		{name: "inherited", sddl: "O:" + user.User.Sid.String() + "D:(A;;GA;;;" + user.User.Sid.String() + ")"},
		{
			name: "another principal",
			sddl: "O:" + user.User.Sid.String() + "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)",
		},
		{name: "no current user", sddl: "O:" + user.User.Sid.String() + "D:P(A;;GA;;;WD)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			descriptor, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)
			assert.ErrorIs(t, validateOwnerOnlyWindowsSecurityDescriptor(descriptor), ErrNotOwnerOnly)
		})
	}
}

func TestOpenOrCreateOwnerOnlyWindowsRejectsInsecureExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	))
	_, err = OpenOrCreateOwnerOnly(path)
	require.ErrorIs(t, err, ErrNotOwnerOnly)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
}

func TestOpenOrCreateOwnerOnlyWindowsCreatesProtectedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	file, err := OpenOrCreateOwnerOnly(path)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	assertOwnerOnlyPath(t, path)
}

func assertOwnerOnlyPath(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	require.NoError(t, err)
	require.NoError(t, validateOwnerOnlyWindowsSecurityDescriptor(descriptor))
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	var ace *windows.ACCESS_ALLOWED_ACE
	require.NoError(t, windows.GetAce(dacl, 0, &ace))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	assert.True(t, aceSID.Equals(user.User.Sid), "ACE SID = %s, want current user %s", aceSID, user.User.Sid)
}
