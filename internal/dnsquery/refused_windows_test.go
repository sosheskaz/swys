package dnsquery_test

import "golang.org/x/sys/windows"

// Windows reports refused connections as WSAECONNREFUSED; syscall.ECONNREFUSED
// is an invented value there that no socket error matches.
var errConnectionRefused error = windows.WSAECONNREFUSED
