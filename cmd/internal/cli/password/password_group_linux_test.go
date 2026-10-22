package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseProcessStatHandlesCommandNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		stat  string
		group int
		state byte
		ok    bool
	}{
		{stat: "12 (sh) T 10 12 12 34816", group: 12, state: 'T', ok: true},
		{stat: "13 (odd) name (x)) S 12 12 12 34816", group: 12, state: 'S', ok: true},
		{stat: "14 (truncated", ok: false},
		{stat: "15 (sh) T 10", ok: false},
	} {
		group, state, ok := parseProcessStat([]byte(test.stat))
		assert.Equal(t, test.ok, ok, "parse %q", test.stat)
		if test.ok {
			assert.Equal(t, test.group, group, "group in %q", test.stat)
			assert.Equal(t, test.state, state, "state in %q", test.stat)
		}
	}
}
