package cmd_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleSkillPrintsInstructionsForInstalledBuild(t *testing.T) {
	t.Parallel()
	output, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "skill")
	require.NoError(t, err, "swys skill")
	require.Empty(t, stderr)
	require.True(t, strings.HasPrefix(string(output), "---\nname: swys\n"), "standalone SKILL.md")
	require.Contains(t, string(output), "swys help cert verify --plain --no-pager")

	version, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "--version")
	require.NoError(t, err)
	build := strings.TrimPrefix(strings.TrimSpace(string(version)), "swys version ")
	require.Contains(t, string(output), "  build: "+strconv.Quote(build))
}

func TestExampleSkillExportsStandaloneInstructions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "SKILL.md")
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "skill", "-o", path)
	require.NoError(t, err, "swys skill -o SKILL.md")
	require.Empty(t, stdout)
	require.Empty(t, stderr)
	saved, err := os.ReadFile(path)
	require.NoError(t, err)
	printed, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "skill")
	require.NoError(t, err)
	require.Equal(t, printed, saved)
}
