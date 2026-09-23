package cmd

import "testing"

func FuzzParseAESChunkSize(f *testing.F) {
	for _, seed := range []string{
		"64",
		"0.0625K",
		"1.5KB",
		"1001",
		"64MiB",
		"63",
		"0.1K",
		"-64",
		"1e3",
		"999999999999999999999999999G",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 128 {
			t.Skip()
		}
		size, err := parseAESChunkSize(value)
		if err == nil && (size < 64 || size > 64*1024*1024) {
			t.Fatalf("parseAESChunkSize(%q) = %d outside the supported range", value, size)
		}
	})
}
