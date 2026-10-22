//go:build !windows

package net_test

import "syscall"

var errConnectionRefused error = syscall.ECONNREFUSED
