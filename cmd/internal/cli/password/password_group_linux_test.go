package password

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:paralleltest // replaces the package procfs root
func TestSupplierWatchWithoutProcfsLetsSupplierFinish(t *testing.T) {
	original := procfsRoot
	procfsRoot = filepath.Join(t.TempDir(), "proc")
	t.Cleanup(func() { procfsRoot = original })
	// The watcher polls the supplier group several times while it runs.
	process := exec.CommandContext(t.Context(), "/bin/sh", "-c", "sleep 0.2")
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, process.Start())
	stop := watchForegroundProcess(t.Context(), process, make(chan os.Signal))
	waitErr := process.Wait()
	result := stop()
	require.NoError(t, result.err)
	assert.False(t, result.suspended)
	assert.NoError(t, waitErr, "the supplier runs to completion")
}

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
