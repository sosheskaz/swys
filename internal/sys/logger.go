// Package sys provides process-level infrastructure shared by commands.
package sys

import (
	"log/slog"

	"github.com/go-logr/logr"
)

var logger logr.Logger

// Log returns the process logger.
func Log() logr.Logger {
	return logger
}

// SetLogger replaces the process logger.
func SetLogger(l logr.Logger) {
	logger = l
}

func init() {
	logger = logr.FromSlogHandler(slog.Default().Handler())
}
