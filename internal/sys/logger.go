package sys

import (
	"log/slog"

	"github.com/go-logr/logr"
)

var logger logr.Logger

func Log() logr.Logger {
	return logger
}

func SetLogger(l logr.Logger) {
	logger = l
}

func init() {
	logger = logr.FromSlogHandler(slog.Default().Handler())
}
