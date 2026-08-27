//go:build windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOwnerOnlyWindowsSecurityDescriptor(t *testing.T) {
	t.Parallel()

	descriptor, err := ownerOnlyWindowsSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerOnlyWindowsSecurityDescriptor(descriptor); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOwnerOnlyWindowsSecurityDescriptorRejectsUnsafeDACLs(t *testing.T) {
	t.Parallel()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			if err := validateOwnerOnlyWindowsSecurityDescriptor(descriptor); !errors.Is(err, ErrNotOwnerOnly) {
				t.Fatalf("error = %v, want ErrNotOwnerOnly", err)
			}
		})
	}
}

func TestOpenOrCreateOwnerOnlyWindowsRejectsInsecureExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOrCreateOwnerOnly(path); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("open error = %v, want ErrNotOwnerOnly", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve" {
		t.Fatalf("contents = %q, want preserved", data)
	}
}

func TestOpenOrCreateOwnerOnlyWindowsCreatesProtectedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	file, err := OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnlyPath(t, path)
}

func assertOwnerOnlyPath(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerOnlyWindowsSecurityDescriptor(descriptor); err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatalf("ACE SID = %s, want current user %s", aceSID, user.User.Sid)
	}
}
