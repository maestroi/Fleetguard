package agent

import (
	"time"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	firewalldsensor "github.com/maestroi/Fleetguard/internal/sensor/firewalld"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector reads the engine's cached Status and sensor Stats at scrape time.
// It never touches the firewall backend, so a scrape cannot cause D-Bus work.
// ponytail: Status() shares the engine mutex; a slow reconcile delays a scrape
// (bounded by the 5s handler timeout). Snapshot status atomically if that bites.
//
// Labels are fixed enums only. No IPs, decision IDs, node IDs or error text.
type Collector struct {
	cfg    RuntimeConfig
	engine *Engine
	sensor *firewalldsensor.Collector // nil when denied-traffic telemetry is off
	now    func() time.Time
}

func NewCollector(c RuntimeConfig, e *Engine, s *firewalldsensor.Collector) *Collector {
	return &Collector{cfg: c, engine: e, sensor: s, now: time.Now}
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("fleetguard_agent_"+name, help, labels, nil)
}

var (
	descInfo           = desc("info", "Build, backend and mode information (always 1).", "version", "backend", "mode")
	descConnected      = desc("controller_connected", "1 if the controller answered within 3 poll intervals.")
	descLastContact    = desc("last_controller_contact_timestamp_seconds", "UNIX time of the last successful controller fetch.")
	descRevision       = desc("policy_revision", "Highest accepted signed policy revision.")
	descAppliedRev     = desc("policy_applied_revision", "Revision last reconciled into the backend.")
	descAcceptedAt     = desc("policy_accepted_timestamp_seconds", "UNIX time the current revision was accepted.")
	descPolicyUpdates  = desc("policy_updates_total", "Signed snapshot outcomes.", "result")
	descActive         = desc("active_decisions", "Desired live decisions by origin.", "origin")
	descEnforced       = desc("enforced_decisions", "Decisions the backend reported as applied on the last reconcile (readback, not intent).")
	descHealthy        = desc("enforcement_healthy", "1 only in enforce mode with a recent error-free reconcile, not disabled and not simulated. Observe mode is always 0.")
	descSimulated      = desc("simulated", "1 if the backend is simulated (observe mode).")
	descDisabled       = desc("emergency_disabled", "1 if the local emergency kill switch is latched.")
	descOfflineExpired = desc("offline_expired", "1 if central policy expired due to controller loss or TTL.")
	descLastError      = desc("last_error", "1 if the most recent policy or reconcile step failed.")
	descReconcileErrs  = desc("firewall_reconcile_errors_total", "Failed reconciles.")
	descLastReconcile  = desc("last_reconcile_timestamp_seconds", "UNIX time of the last successful reconcile.")
	descSensorLines    = desc("sensor_lines_total", "Denied-traffic journal lines by parse result.", "result")
	descSensorDropped  = desc("sensor_events_dropped_total", "Denied-traffic data dropped by bound.", "reason")
	descSensorEmitted  = desc("sensor_reports_emitted_total", "Denied-traffic evidence reports emitted.")
	descSensorJournal  = desc("sensor_journal_failures_total", "Journal reader failures.")
	descSensorSources  = desc("sensor_active_sources", "Sources tracked in the current window.")

	// Fleet never-ban protection; emitted only when a protection anchor is configured.
	descProtRequired  = desc("protection_required", "1 if new bans require a fresh fleet never-ban list.")
	descProtRevision  = desc("protection_revision", "Accepted fleet never-ban revision (0 = none).")
	descProtEntries   = desc("protection_entries", "Protected prefixes currently retained.")
	descProtFresh     = desc("protection_fresh", "1 if the accepted fleet never-ban list is unexpired.")
	descProtExpires   = desc("protection_expires_timestamp_seconds", "UNIX expiry of the accepted fleet never-ban list.")
	descProtUpdated   = desc("protection_last_update_timestamp_seconds", "UNIX time the current fleet never-ban list was accepted.")
	descProtUnverif   = desc("protection_unverified", "1 if retained protections no longer verify against the configured anchor.")
	descProtWithheld  = desc("protection_withheld_decisions", "Central decisions withheld because they overlap a protection.")
	descProtUpdates   = desc("protection_updates_total", "Fleet never-ban update outcomes.", "result")
	descRejected      = desc("decisions_rejected_total", "Ban decisions refused by fleet protection, by bounded reason.", "reason")
	descRejectedCat   = desc("protection_rejections_by_category_total", "protected_source refusals by the matching protection category.", "category")
	descProtRemovals  = desc("protection_conflict_removals_total", "Installed bans removed because a protection now covers them.")
	descProtCleanFail = desc("protection_cleanup_failures_total", "Reconciles where the backend still reported a protected ban.")
)

func (c *Collector) Describe(ch chan<- *prometheus.Desc) { prometheus.DescribeByCollect(c, ch) }

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	st := c.engine.Status()
	now := c.now()
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v uint64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), labels...)
	}
	ts := func(d *prometheus.Desc, t time.Time) {
		if !t.IsZero() { // absent rather than 1970 when never happened
			gauge(d, float64(t.UnixNano())/1e9)
		}
	}
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}

	gauge(descInfo, 1, buildinfo.Version, c.cfg.FirewallBackend, c.cfg.Mode)
	poll := time.Duration(c.cfg.PollIntervalSeconds) * time.Second
	gauge(descConnected, b(!st.LastContact.IsZero() && now.Sub(st.LastContact) <= 3*poll))
	ts(descLastContact, st.LastContact)
	gauge(descRevision, float64(st.Revision))
	gauge(descAppliedRev, float64(st.LastAppliedRevision))
	ts(descAcceptedAt, st.LastAcceptedAt)
	counter(descPolicyUpdates, st.AcceptedSnapshots, "accepted")
	counter(descPolicyUpdates, st.InvalidSnapshots, "invalid")
	counter(descPolicyUpdates, st.RejectedScopes, "scope_denied")
	gauge(descActive, float64(st.CentralDecisions), "central")
	gauge(descActive, float64(st.LocallyJustified), "local")
	gauge(descEnforced, float64(st.ActiveDecisions))
	reconcile := time.Duration(c.cfg.ReconcileIntervalSeconds) * time.Second
	healthy := st.Mode == "enforce" && !st.Simulated && !st.Disabled && st.LastError == "" &&
		!st.LastReconcile.IsZero() && now.Sub(st.LastReconcile) <= 3*reconcile
	gauge(descHealthy, b(healthy))
	gauge(descSimulated, b(st.Simulated))
	gauge(descDisabled, b(st.Disabled))
	gauge(descOfflineExpired, b(st.OfflineExpired))
	gauge(descLastError, b(st.LastError != ""))
	counter(descReconcileErrs, st.ReconcileErrors)
	ts(descLastReconcile, st.LastReconcile)

	if c.cfg.NeverBanKeysFile != "" {
		fresh := st.ProtectionRevision > 0 && !st.ProtectionUnverified && st.ProtectionExpiresAt.After(now)
		gauge(descProtRequired, b(c.cfg.NeverBanRequired))
		gauge(descProtRevision, float64(st.ProtectionRevision))
		gauge(descProtEntries, float64(st.ProtectionEntries))
		gauge(descProtFresh, b(fresh))
		ts(descProtExpires, st.ProtectionExpiresAt)
		ts(descProtUpdated, st.ProtectionAcceptedAt)
		gauge(descProtUnverif, b(st.ProtectionUnverified))
		gauge(descProtWithheld, float64(st.ProtectedWithheld))
		counter(descProtUpdates, st.ProtectionUpdates, "accepted")
		counter(descProtUpdates, st.InvalidProtection, "invalid")
		counter(descRejected, st.RejectedProtectedSource, "protected_source")
		counter(descRejected, st.RejectedProtectionStale, "protection_stale")
		for i, category := range ProtectionCategories {
			counter(descRejectedCat, st.RejectedByCategory[i], string(category))
		}
		counter(descProtRemovals, st.ProtectionRemovals)
		counter(descProtCleanFail, st.ProtectionCleanupFailures)
	}

	if c.sensor == nil {
		return
	}
	s := c.sensor.Stats()
	counter(descSensorLines, s.Parsed, "parsed")
	counter(descSensorLines, s.Ignored, "ignored")
	counter(descSensorLines, s.Malformed, "malformed")
	counter(descSensorLines, s.Oversized, "oversized")
	counter(descSensorLines, s.Unmapped, "unmapped")
	counter(descSensorDropped, s.DroppedPackets, "packet_cap")
	counter(descSensorDropped, s.DroppedSources, "source_cap")
	counter(descSensorDropped, s.DroppedPorts, "port_cap")
	counter(descSensorDropped, s.DroppedReports, "report_cap")
	counter(descSensorDropped, s.QueueDropped, "queue_full")
	counter(descSensorDropped, s.SubmitFailed, "submit_failed")
	counter(descSensorEmitted, s.Emitted)
	counter(descSensorJournal, s.JournalFailures)
	gauge(descSensorSources, float64(s.ActiveSources))
}
