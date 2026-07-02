// Package version reports the binary's provenance, preferring values
// injected by release ldflags and falling back to the VCS metadata the Go
// toolchain embeds in ad-hoc builds.
package version

import (
	"runtime/debug"
	"strings"
)

// Injected by goreleaser via -ldflags="-X ...". Empty in ad-hoc builds,
// where Get falls back to debug.ReadBuildInfo.
var (
	version = ""
	commit  = ""
	date    = ""
)

// Info describes how the running binary was built.
type Info struct {
	Version  string
	Commit   string
	Date     string
	Modified bool
}

// Get resolves build provenance. Release builds carry exact values from
// goreleaser; ad-hoc `go build` binaries report the module version the
// toolchain derived plus VCS revision, timestamp, and dirty state.
func Get() Info {
	info := Info{Version: version, Commit: commit, Date: date}
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if info.Version == "" {
		info.Version = buildInfo.Main.Version
	}
	for _, setting := range buildInfo.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = setting.Value
			}
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		}
	}
	return info
}

// String renders the info as a single human-readable line, omitting fields
// that are unavailable for this build.
func (i Info) String() string {
	var b strings.Builder
	if i.Version != "" {
		b.WriteString(i.Version)
	} else {
		b.WriteString("unknown")
	}

	var details []string
	if i.Commit != "" {
		short := i.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		details = append(details, "commit "+short)
	}
	if i.Date != "" {
		details = append(details, "built "+i.Date)
	}
	if i.Modified {
		details = append(details, "dirty")
	}
	if len(details) > 0 {
		b.WriteString(" (" + strings.Join(details, ", ") + ")")
	}
	return b.String()
}
