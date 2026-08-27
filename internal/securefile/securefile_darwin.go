//go:build darwin

package securefile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	darwinFileSecurityMagic       = 0x012cc16d
	darwinIdentityNone            = ^uint32(0) - 100
	darwinACLNoEntries            = ^uint32(0)
	darwinACLNoInherit            = 1 << 17
	darwinFileSecuritySize        = 44
	darwinACLEntryCountOffset     = 36
	darwinACLFlagsOffset          = 40
	darwinReturnedAttributesSize  = 20
	darwinAttributeResponseHeader = 4 + darwinReturnedAttributesSize
	darwinMaxAttributeResponse    = darwinAttributeResponseHeader + 8 + darwinFileSecuritySize + 128*24
)

var (
	errMalformedDarwinAttributeResponse = errors.New("malformed Darwin attribute response")
	errWrapOwnerOnlyFileDescriptor      = errors.New("wrap owner-only file descriptor")
)

// OpenOrCreateOwnerOnly opens path for writing without truncating it. A missing
// path is created without inherited ACLs; an existing regular file must already
// be owned by the effective user and grant access through owner mode bits only.
func OpenOrCreateOwnerOnly(path string) (*os.File, error) {
	file, err := openDarwinOwnerOnly(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, file.Close())
	}

	regular, err := validateUnixOwnerOnly(file)
	if err != nil {
		return fail(err)
	}
	if !regular {
		return file, nil
	}
	hasACL, err := hasDarwinExtendedACL(file)
	if err != nil {
		return fail(fmt.Errorf("inspect owner-only ACL: %w", err))
	}
	if hasACL {
		return fail(fmt.Errorf("%w: extended ACL entries are set", ErrNotOwnerOnly))
	}
	return file, nil
}

func openDarwinOwnerOnly(path string) (*os.File, error) {
	file, err := createDarwinOwnerOnly(path)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}

	file, err = os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // caller-supplied output paths are this API's intended input
	if err != nil {
		return nil, fmt.Errorf("open existing owner-only file: %w", err)
	}
	return file, nil
}

func createDarwinOwnerOnly(path string) (*os.File, error) {
	pathPointer, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	security := make([]byte, darwinFileSecuritySize)
	binary.NativeEndian.PutUint32(security[0:4], darwinFileSecurityMagic)
	binary.NativeEndian.PutUint32(security[darwinACLEntryCountOffset:darwinACLFlagsOffset], darwinACLNoEntries)
	binary.NativeEndian.PutUint32(security[darwinACLFlagsOffset:darwinFileSecuritySize], darwinACLNoInherit)

	fd, _, errno := unix.Syscall6(
		unix.SYS_OPEN_EXTENDED, //nolint:staticcheck // x/sys has no open_extended wrapper for atomic no-inherit ACL creation
		uintptr(unsafe.Pointer(pathPointer)),
		uintptr(unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC),
		uintptr(darwinIdentityNone),
		uintptr(darwinIdentityNone),
		0o600,
		uintptr(unsafe.Pointer(&security[0])),
	)
	runtime.KeepAlive(pathPointer)
	runtime.KeepAlive(security)
	if errno != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: errno}
	}
	file := os.NewFile(fd, path)
	if file == nil {
		return nil, errors.Join(errWrapOwnerOnlyFileDescriptor, unix.Close(int(fd)))
	}
	return file, nil
}

func hasDarwinExtendedACL(file *os.File) (bool, error) {
	attributes := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY,
	}
	buffer := make([]byte, darwinMaxAttributeResponse)
	_, _, errno := unix.Syscall6(
		unix.SYS_FGETATTRLIST, //nolint:staticcheck // x/sys has no fgetattrlist wrapper for descriptor-bound ACL inspection
		file.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		unix.FSOPT_REPORT_FULLSIZE,
		0,
	)
	runtime.KeepAlive(file)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return false, errno
	}
	common, err := darwinReturnedCommonAttributes(buffer)
	if err != nil {
		return false, err
	}
	return common&unix.ATTR_CMN_EXTENDED_SECURITY != 0, nil
}

func darwinReturnedCommonAttributes(buffer []byte) (uint32, error) {
	if len(buffer) < darwinAttributeResponseHeader {
		return 0, fmt.Errorf("%w: missing header", errMalformedDarwinAttributeResponse)
	}
	reportedSize := binary.NativeEndian.Uint32(buffer[0:4])
	if reportedSize < darwinAttributeResponseHeader {
		return 0, fmt.Errorf("%w: reported size %d is too small", errMalformedDarwinAttributeResponse, reportedSize)
	}
	if uint64(reportedSize) > uint64(len(buffer)) {
		return 0, fmt.Errorf("%w: reported size %d exceeds buffer size %d", errMalformedDarwinAttributeResponse, reportedSize, len(buffer))
	}
	common := binary.NativeEndian.Uint32(buffer[4:8])
	if common&unix.ATTR_CMN_RETURNED_ATTRS == 0 {
		return 0, fmt.Errorf("%w: missing returned-attributes metadata", errMalformedDarwinAttributeResponse)
	}
	return common, nil
}
