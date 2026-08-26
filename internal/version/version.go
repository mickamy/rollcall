package version

import (
	"runtime/debug"
	"strings"
)

func String() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return "dev"
	}

	return strings.TrimSuffix(v, "+dirty") + dirtySuffix(info)
}

func dirtySuffix(info *debug.BuildInfo) string {
	for _, s := range info.Settings {
		if s.Key == "vcs.modified" && s.Value == "true" {
			return " (modified)"
		}
	}

	return ""
}
