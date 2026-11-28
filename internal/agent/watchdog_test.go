package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchdogPingsOnlyAfterSuccessfulReconcile(t *testing.T) {
	var sent []time.Time
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	w := &watchdog{interval: 60 * time.Second, notify: func(state string) (bool, error) {
		if state != "WATCHDOG=1" {
			t.Fatalf("unexpected state %q", state)
		}
		sent = append(sent, now)
		return true, nil
	}}
	w.reconciled(errors.New("D-Bus timeout"), now)
	if len(sent) != 0 {
		t.Fatal("pinged after failed reconcile")
	}
	w.reconciled(nil, now)
	now = now.Add(5 * time.Second)
	w.reconciled(nil, now) // throttled: < interval/3
	if len(sent) != 1 {
		t.Fatalf("pings %d, want 1", len(sent))
	}
	// Persistent failure: no pings for a full interval, so systemd would kill.
	for i := 0; i < 12; i++ {
		now = now.Add(5 * time.Second)
		w.reconciled(errors.New("reconcile failing"), now)
	}
	if len(sent) != 1 {
		t.Fatal("failing reconciles kept the watchdog alive")
	}
	now = now.Add(5 * time.Second)
	w.reconciled(nil, now)
	if len(sent) != 2 || !w.lastPingTime().Equal(now) {
		t.Fatal("recovery did not resume pings")
	}
	var disabled *watchdog
	disabled.reconciled(nil, now) // nil-safe when not under systemd
}

func TestWatchdogIntervalMustCoverReconcileAndTimeout(t *testing.T) {
	t.Setenv("WATCHDOG_PID", "")
	t.Setenv("WATCHDOG_USEC", "20000000") // 20s
	if _, err := newWatchdog(5*time.Second, 15*time.Second); err == nil {
		t.Fatal("WatchdogSec shorter than 3x reconcile + timeout accepted")
	}
	t.Setenv("WATCHDOG_USEC", "60000000")
	w, err := newWatchdog(5*time.Second, 15*time.Second)
	if err != nil || w == nil || w.interval != time.Minute {
		t.Fatal(w, err)
	}
	t.Setenv("WATCHDOG_USEC", "")
	if w, err := newWatchdog(5*time.Second, 15*time.Second); w != nil || err != nil {
		t.Fatal("watchdog must be off outside systemd")
	}
}

func TestCleanupOwnedObserveIsNoopAndBadConfigFails(t *testing.T) {
	dir := t.TempDir()
	observe := filepath.Join(dir, "observe.json")
	cfg := `{"node_id":"lab-node-a","service_group":"lab-ssh","mode":"observe","firewall_backend":"simulated",
"controller_url":"https://127.0.0.1:9443","tls_ca_file":"/tmp/ca.pem","token_file":"/tmp/token","trusted_keys_file":"/tmp/k.json",
"safety_policy_file":"/tmp/s.json","state_dir":"/tmp/state","poll_interval_seconds":5,"reconcile_interval_seconds":5,"max_offline_age_seconds":60}`
	if err := os.WriteFile(observe, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupOwned(context.Background(), observe); err != nil {
		t.Fatalf("observe cleanup should be a no-op: %v", err)
	}
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"mode":"enforce"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupOwned(context.Background(), broken); err == nil {
		t.Fatal("invalid config accepted")
	}
}
