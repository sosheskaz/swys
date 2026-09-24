//go:build !windows

package dnsquery

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfiguredDNSServers(t *testing.T) {
	t.Parallel()

	servers, err := parseConfiguredDNSServers(strings.NewReader(
		"search example.test\n# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # local\n",
	))
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.53", "2001:db8::53"}, servers)
}
