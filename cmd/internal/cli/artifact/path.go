package artifact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SamePath detects existing path aliases and compares destinations whose final
// component does not yet exist. This is a preflight check; paths can change
// before the caller opens them.
func SamePath(left, right string) (bool, error) {
	leftInfo, leftErr := os.Stat(left)
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", left, leftErr)
	}
	rightInfo, rightErr := os.Stat(right)
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", right, rightErr)
	}
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}
	if leftErr == nil || rightErr == nil {
		return false, nil
	}
	leftCanonical, err := canonicalPath(left)
	if err != nil {
		return false, err
	}
	rightCanonical, err := canonicalPath(right)
	if err != nil {
		return false, err
	}
	return leftCanonical == rightCanonical, nil
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	info, lstatErr := os.Lstat(absolute)
	if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		target, readErr := os.Readlink(absolute)
		if readErr != nil {
			return "", fmt.Errorf("resolve symlink %q: %w", path, readErr)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(absolute), target)
		}
		return canonicalPath(target)
	}
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect path %q: %w", path, lstatErr)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return filepath.Clean(absolute), nil
		}
		return "", fmt.Errorf("resolve parent of path %q: %w", path, err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}
