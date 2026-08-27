//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errWrapFileHandle = errors.New("wrap secure file handle")

// OpenOrCreateOwnerOnly opens path for writing without truncating it. A missing
// path is created with the owner-only DACL; an existing regular file must
// already have a protected DACL that grants access only to the current user.
func OpenOrCreateOwnerOnly(path string) (*os.File, error) {
	descriptor, err := ownerOnlyWindowsSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	handle, err := createWindowsFile(path, descriptor, windows.OPEN_ALWAYS, windows.GENERIC_WRITE|windows.READ_CONTROL)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(errWrapFileHandle, windows.CloseHandle(handle))
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, file.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect owner-only file: %w", err))
	}
	if !info.Mode().IsRegular() {
		return file, nil
	}
	openedDescriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fail(fmt.Errorf("read owner-only Windows security descriptor: %w", err))
	}
	if err := validateOwnerOnlyWindowsSecurityDescriptor(openedDescriptor); err != nil {
		return fail(err)
	}
	return file, nil
}

func createWindowsFile(path string, descriptor *windows.SECURITY_DESCRIPTOR, disposition, access uint32) (windows.Handle, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, &os.PathError{Op: "open", Path: path, Err: err}
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
		0,
		&attributes,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return windows.InvalidHandle, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return handle, nil
}

func ownerOnlyWindowsSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current Windows user: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + user.User.Sid.String() + "D:P(A;;GA;;;" + user.User.Sid.String() + ")",
	)
	if err != nil {
		return nil, fmt.Errorf("create owner-only Windows security descriptor: %w", err)
	}
	return descriptor, nil
}

func validateOwnerOnlyWindowsSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return fmt.Errorf("%w: security descriptor is missing", ErrNotOwnerOnly)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current Windows user: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read Windows security descriptor owner: %w", err)
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return fmt.Errorf("%w: file is not owned by the current user", ErrNotOwnerOnly)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read Windows security descriptor control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: DACL inherits permissions", ErrNotOwnerOnly)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read Windows DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: DACL is missing", ErrNotOwnerOnly)
	}
	foundCurrentUser := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read Windows DACL ACE %d: %w", index, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !aceSID.Equals(user.User.Sid) {
				return fmt.Errorf("%w: DACL grants access to another principal", ErrNotOwnerOnly)
			}
			foundCurrentUser = true
		case windows.ACCESS_DENIED_ACE_TYPE:
			// Deny entries do not grant another principal access.
		default:
			return fmt.Errorf("%w: DACL contains an unsupported ACE type", ErrNotOwnerOnly)
		}
	}
	if !foundCurrentUser {
		return fmt.Errorf("%w: DACL does not grant the current user access", ErrNotOwnerOnly)
	}
	return nil
}
