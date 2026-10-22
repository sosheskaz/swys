//go:build !windows

package dnsquery_test

import "syscall"

var errConnectionRefused error = syscall.ECONNREFUSED
