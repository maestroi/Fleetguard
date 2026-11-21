// Package buildinfo holds reproducible, linker-injected build metadata.
package buildinfo

import "fmt"

// These values can be overridden with go build -ldflags -X.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func String(component string) string {
	return fmt.Sprintf("%s %s (commit=%s, built=%s)", component, Version, Commit, BuildDate)
}
