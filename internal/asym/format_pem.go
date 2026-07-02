package asym

import (
	"encoding/pem"
	"io"
)

// PEMFormatter outputs the raw PEM certificate only.
type PEMFormatter struct{}

// Format writes a single certificate as PEM.
func (f *PEMFormatter) Format(info *CertInfo, w io.Writer) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: info.RawDER,
	}
	return pem.Encode(w, block)
}

// FormatMultiple writes multiple certificates as PEM blocks.
func (f *PEMFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	for _, info := range infos {
		if err := f.Format(info, w); err != nil {
			return err
		}
	}
	return nil
}
