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

	"golang.org/x/sys/unix"
)

func TestOpenOrCreateOwnerOnlyRejectsExistingDarwinACL(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, path, "everyone allow read")

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

func TestOpenOrCreateOwnerOnlyRejectsCurrentUserDarwinACL(t *testing.T) {
	t.Parallel()

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, path, current.Username+" allow read")

	if _, err := OpenOrCreateOwnerOnly(path); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("open error = %v, want ErrNotOwnerOnly", err)
	}
}

func TestOpenOrCreateOwnerOnlySuppressesInheritedDarwinACL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	addDarwinACL(t, dir, "everyone allow read,file_inherit")
	path := filepath.Join(dir, "private.key")
	file, err := OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
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
			if _, err := darwinReturnedCommonAttributes(tt.buffer); err == nil {
				t.Fatal("error = nil, want malformed response error")
			}
		})
	}

	buffer := darwinAttributeResponse(
		darwinAttributeResponseHeader,
		unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY,
	)
	common, err := darwinReturnedCommonAttributes(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if common&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		t.Fatalf("common attributes = %#x, want extended security", common)
	}
}

func FuzzDarwinReturnedCommonAttributes(f *testing.F) {
	f.Add(darwinAttributeResponse(darwinAttributeResponseHeader, unix.ATTR_CMN_RETURNED_ATTRS))
	f.Add(darwinAttributeResponse(
		darwinAttributeResponseHeader,
		unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY,
	))
	f.Fuzz(func(_ *testing.T, buffer []byte) {
		if _, err := darwinReturnedCommonAttributes(buffer); err != nil {
			return
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
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	hasACL, err := hasDarwinExtendedACL(file)
	if err != nil {
		t.Fatal(err)
	}
	if hasACL {
		t.Fatal("new file inherited an extended ACL")
	}
}
