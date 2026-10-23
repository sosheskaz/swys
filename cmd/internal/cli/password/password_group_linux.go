package password

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procfsRoot is a variable so tests can simulate a host without procfs mounted.
var procfsRoot = "/proc"

// passwordGroupStopped reports whether any process in process group pgid is stopped.
func passwordGroupStopped(pgid int) (bool, error) {
	entries, err := os.ReadDir(procfsRoot)
	if err != nil {
		return false, fmt.Errorf("list processes: %w", err)
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(procfsRoot, entry.Name(), "stat"))
		if err != nil {
			continue // the process exited
		}
		if group, state, ok := parseProcessStat(stat); ok && group == pgid && state == 'T' {
			return true, nil
		}
	}
	return false, nil
}

// parseProcessStat returns the process group and state from /proc/<pid>/stat,
// whose parenthesized command field may itself contain spaces and parentheses.
func parseProcessStat(stat []byte) (int, byte, bool) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, 0, false
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 3 || len(fields[0]) != 1 {
		return 0, 0, false
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, 0, false
	}
	return group, fields[0][0], true
}
