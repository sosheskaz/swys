package cmd

import (
	"fmt"

	"github.com/sosheskaz/cryptool/internal/asym"
)

// certFormatters maps format names to formatter constructors.
var certFormatters = map[string]func() asym.CertFormatter{
	"text":      func() asym.CertFormatter { return &asym.TextFormatter{Long: false} },
	"long":      func() asym.CertFormatter { return &asym.TextFormatter{Long: true} },
	"json":      func() asym.CertFormatter { return &asym.JSONFormatter{} },
	"pem":       func() asym.CertFormatter { return &asym.PEMFormatter{} },
	"chain":     func() asym.CertFormatter { return &asym.ChainPEMFormatter{} },
	"fullchain": func() asym.CertFormatter { return &asym.FullChainPEMFormatter{} },
}

// GetCertFormatter returns a formatter for the given format name.
func GetCertFormatter(format string) (asym.CertFormatter, error) {
	if constructor, ok := certFormatters[format]; ok {
		return constructor(), nil
	}
	return nil, fmt.Errorf("unknown output format: %s (valid formats: text, long, json, pem, chain, fullchain)", format)
}
