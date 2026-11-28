package agent

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/internal/sdnotify"
)

// watchdog pings systemd (WATCHDOG=1) only after a SUCCESSFUL reconcile.
// A hung reconcile, a wedged D-Bus write, or a reconcile that keeps failing
// stops the pings, so systemd kills the agent and ExecStopPost cleanup
// removes owned bans independently of this process. Liveness alone never
// counts as health.
type watchdog struct {
	interval time.Duration
	last     time.Time
	notify   func(string) (bool, error)
	lastPing atomic.Int64 // unix nanos, read by metrics
}

// newWatchdog returns nil unless systemd enabled WatchdogSec for this PID.
// It refuses intervals too short to survive a few reconcile periods plus a
// bounded backend timeout, which would turn transient slowness into kills.
func newWatchdog(reconcileEvery, reconcileTimeout time.Duration) (*watchdog, error) {
	interval, ok := sdnotify.WatchdogInterval()
	if !ok {
		return nil, nil
	}
	if minimum := 3*reconcileEvery + reconcileTimeout; interval < minimum {
		return nil, fmt.Errorf("systemd WatchdogSec %v must be at least %v (3x reconcile interval + reconcile timeout)", interval, minimum)
	}
	return &watchdog{interval: interval, notify: sdnotify.Notify}, nil
}

func (w *watchdog) reconciled(err error, now time.Time) {
	if w == nil || err != nil {
		return
	}
	if !w.last.IsZero() && now.Sub(w.last) < w.interval/3 {
		return
	}
	if sent, _ := w.notify("WATCHDOG=1"); sent {
		w.last = now
		w.lastPing.Store(now.UnixNano())
	}
}

func (w *watchdog) lastPingTime() time.Time {
	if w == nil {
		return time.Time{}
	}
	if n := w.lastPing.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// CleanupOwned removes only Fleetguard-owned runtime firewalld objects using
// the installed runtime config, independently of any (possibly hung or
// killed) agent process. It is meant for systemd ExecStopPost=. Observe-mode
// configs have nothing to clean and succeed.
func CleanupOwned(ctx context.Context, configPath string) error {
	c, err := LoadRuntimeConfig(configPath)
	if err != nil {
		return err
	}
	if c.Mode != "enforce" {
		return nil
	}
	if err := safety.CheckRootOwnedFile(configPath); err != nil {
		return err
	}
	policy, err := c.LoadPolicy()
	if err != nil {
		return err
	}
	backend, closeBackend, err := BuildRealBackend(c, policy)
	if err != nil {
		return errors.Join(errors.New("cleanup: firewalld backend unavailable"), err)
	}
	defer closeBackend()
	return backend.RemoveOwned(ctx)
}
