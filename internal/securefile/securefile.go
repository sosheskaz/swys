// Package securefile provides the platform-specific mechanics used to create
// files that contain private cryptographic material.
package securefile

import "errors"

// ErrNotOwnerOnly reports that an existing regular file does not satisfy the
// owner-only access policy.
var ErrNotOwnerOnly = errors.New("file is not owner-only")
