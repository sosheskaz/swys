package version

import (
	"strings"
	"testing"
)

func TestInfoString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		info Info
	}{
		{
			name: "release build",
			info: Info{Version: "1.2.3", Commit: "0123456789abcdef0123", Date: "2026-07-02T17:00:00Z"},
			want: "1.2.3 (commit 0123456789ab, built 2026-07-02T17:00:00Z)",
		},
		{
			name: "ad-hoc dirty build",
			info: Info{Version: "(devel)", Commit: "0123456789abcdef0123", Modified: true},
			want: "(devel) (commit 0123456789ab, dirty)",
		},
		{
			name: "short commit is not truncated",
			info: Info{Version: "1.0.0", Commit: "abc1234"},
			want: "1.0.0 (commit abc1234)",
		},
		{
			name: "version only",
			info: Info{Version: "1.0.0"},
			want: "1.0.0",
		},
		{
			name: "nothing known",
			info: Info{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.info.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetReportsAVersion(t *testing.T) {
	t.Parallel()
	info := Get()
	if info.Version == "" {
		t.Fatal("Get() returned an empty version; expected ldflags value or build-info fallback")
	}
	if strings.Contains(info.String(), "  ") {
		t.Fatalf("String() contains doubled spaces: %q", info.String())
	}
}
