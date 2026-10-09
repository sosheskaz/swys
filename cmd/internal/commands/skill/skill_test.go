package skill

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/version"
)

func TestRenderPreservesBuildProvenance(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		info version.Info
	}{
		{name: "release", info: version.Info{Version: "0.2.0", Commit: "0123456789abcdef", Date: "2026-10-08T12:00:00Z"}},
		{name: "snapshot", info: version.Info{Version: "0.2.0-SNAPSHOT-abcd"}},
		{name: "development", info: version.Info{Version: "(devel)", Commit: "abcdef", Modified: true}},
		{name: "unknown"},
		{name: "quoted build values", info: version.Info{Version: "test\"\n: # value\\", Commit: "a\"b", Date: "\tdate"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := render(test.info)
			require.NoError(t, err)
			wantVersion := test.info.Version
			if wantVersion == "" {
				wantVersion = "unknown"
			}
			for key, want := range map[string]string{"version": wantVersion, "build": test.info.String()} {
				_, value, ok := strings.Cut(string(output), "\n  "+key+": ")
				require.True(t, ok, "missing provenance field %s", key)
				line, _, _ := strings.Cut(value, "\n")
				var got string
				require.NoError(t, json.Unmarshal([]byte(line), &got), "quoted field %s", key)
				assert.Equal(t, want, got, "field %s", key)
			}
		})
	}
}
