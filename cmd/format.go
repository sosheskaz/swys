package cmd

import (
	"fmt"
	"io"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

var certFormatters = map[string]func() asym.CertFormatter{
	"text":      func() asym.CertFormatter { return &asym.TextFormatter{} },
	"long":      func() asym.CertFormatter { return &asym.TextFormatter{Long: true} },
	"json":      func() asym.CertFormatter { return &asym.JSONFormatter{Indent: true} },
	"pem":       func() asym.CertFormatter { return &asym.PEMFormatter{} },
	"chain":     func() asym.CertFormatter { return &asym.ChainPEMFormatter{} },
	"fullchain": func() asym.CertFormatter { return &asym.PEMFormatter{FullChain: true} },
}

func getCertFormatter(format string) (asym.CertFormatter, error) {
	constructor, ok := certFormatters[format]
	if !ok {
		return nil, fmt.Errorf("unknown output format %q (valid formats: text, long, json, pem, chain, fullchain)", format)
	}
	return constructor(), nil
}

func formatCertificates(formatter asym.CertFormatter, infos []*asym.CertInfo, output io.Writer) error {
	if len(infos) == 1 {
		return formatter.Format(infos[0], output)
	}
	return formatter.FormatMultiple(infos, output)
}
