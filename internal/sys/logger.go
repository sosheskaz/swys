// Package sys provides process-level infrastructure shared by commands.
package sys

import "log/slog"

var logger = slog.Default()

// Log returns the process logger.
func Log() *slog.Logger {
	return logger
}

// SetLogger replaces the process logger.
func SetLogger(l *slog.Logger) {
	logger = l
}
