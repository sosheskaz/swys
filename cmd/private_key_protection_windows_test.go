//go:build windows

package cmd

import (
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
	assertOwnerOnlyWindowsSecurityDescriptor(t, descriptor)
}

func assertPrivateKeyProtection(t *testing.T, path string) {
	t.Helper()

	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read private key security descriptor: %v", err)
	}
	assertOwnerOnlyWindowsSecurityDescriptor(t, descriptor)
}

func assertOwnerOnlyWindowsSecurityDescriptor(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) {
	t.Helper()

	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read private key security descriptor control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("private key DACL inherits permissions: control=%#x descriptor=%s", control, descriptor)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read private key DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("private key DACL is nil")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("private key DACL ACE count = %d, want 1", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("read private key DACL ACE: %v", err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("private key ACE type = %d, want allow", ace.Header.AceType)
	}
	const fileAllAccess = windows.ACCESS_MASK(0x001f01ff)
	if ace.Mask != windows.GENERIC_ALL && ace.Mask != fileAllAccess {
		t.Fatalf("private key ACE mask = %#x, want generic all", ace.Mask)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read current Windows user: %v", err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatalf("private key ACE SID = %s, want current user %s", aceSID, user.User.Sid)
	}
}
