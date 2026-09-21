// Package contextio lets a caller stop waiting on a blocked read or open when
// its context is done. Cancellation stops the wait, not the operation: a call
// already blocked in the operating system finishes on a helper goroutine and its
// result is discarded. A reader never closes its borrowed input; an abandoned
// open closes a file returned after cancellation.
package contextio
