//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errWrapPrivateKeyFileHandle = errors.New("wrap private key file handle")

func openExclusivePrivateKey(path string) (*os.File, error) {
	descriptor, err := ownerOnlyWindowsSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, fmt.Errorf("read owner-only Windows DACL: %w", err)
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_WRITE|windows.WRITE_DAC,
		0,
		&attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	discard := func(cause error) error {
		closeErr := windows.CloseHandle(handle)
		removeErr := os.Remove(path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return errors.Join(cause, closeErr, removeErr)
	}
	// Reapply the DACL through the private handle so inheritance is disabled before key bytes are written.
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		runtime.KeepAlive(descriptor)
		return nil, discard(fmt.Errorf("protect owner-only Windows DACL: %w", err))
	}
	runtime.KeepAlive(descriptor)
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, discard(errWrapPrivateKeyFileHandle)
	}
	return file, nil
}

func ownerOnlyWindowsSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current Windows user: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + user.User.Sid.String() + ")",
	)
	if err != nil {
		return nil, fmt.Errorf("create owner-only Windows security descriptor: %w", err)
	}
	return descriptor, nil
}
