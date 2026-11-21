package agent

import "github.com/maestroi/Fleetguard/internal/safety"

// Root-only operator latch checking must never treat an error as safe.
func checkEmergencyDir(dir string) (bool, error) {
	return safety.Disabled(dir)
}
