package agent

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// scrape goes through the real /metrics handler and the Prometheus text parser.
func scrape(t *testing.T, c *Collector) (string, map[string]float64) {
	t.Helper()
	reg := metrics.NewRegistry()
	reg.MustRegister(c)
	if problems, err := testutil.GatherAndLint(reg); err != nil || len(problems) != 0 {
		t.Fatalf("metric lint: %v %+v", err, problems)
	}
	rec := httptest.NewRecorder()
	metrics.Handler(reg).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for name, f := range families {
		if !strings.HasPrefix(name, "fleetguard_") {
			continue
		}
		for _, m := range f.GetMetric() {
			key := name
			for _, l := range m.GetLabel() {
				if l.GetName() != "version" {
					key += "," + l.GetName() + "=" + l.GetValue()
				}
			}
			switch {
			case m.Gauge != nil:
				out[key] = m.GetGauge().GetValue()
			case m.Counter != nil:
				out[key] = m.GetCounter().GetValue()
			}
		}
	}
	return string(body), out
}

func expect(t *testing.T, got map[string]float64, want map[string]float64) {
	t.Helper()
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v (present=%v), want %v", k, g, ok, v)
		}
	}
}

func TestMetricsObserveModeCountsOutcomesWithoutLeakingIdentifiers(t *testing.T) {
	e, _, now, priv, _ := fixture(t, "observe")
	cfg := RuntimeConfig{Mode: "observe", FirewallBackend: "simulated", PollIntervalSeconds: 5, ReconcileIntervalSeconds: 1}
	c := NewCollector(cfg, e, nil)
	c.now = func() time.Time { return *now }

	_, before := scrape(t, c)
	expect(t, before, map[string]float64{"fleetguard_agent_controller_connected": 0, "fleetguard_agent_policy_revision": 0})
	if _, ok := before["fleetguard_agent_last_controller_contact_timestamp_seconds"]; ok {
		t.Fatal("never-contacted agent must omit contact timestamp, not report 1970")
	}

	e.MarkContact()
	valid := snapshot(t, priv, *now, 1, "203.0.113.42/32")
	if _, err := e.Accept(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	forged := valid
	forged.SignatureBase64 = valid.PayloadBase64
	_, _ = e.Accept(context.Background(), forged)
	_, _ = e.Accept(context.Background(), snapshot(t, priv, *now, 2, "10.5.6.7/32")) // protected CIDR

	body, got := scrape(t, c)
	expect(t, got, map[string]float64{
		"fleetguard_agent_info,backend=simulated,mode=observe":      1,
		"fleetguard_agent_controller_connected":                     1,
		"fleetguard_agent_policy_revision":                          1,
		"fleetguard_agent_policy_applied_revision":                  1,
		"fleetguard_agent_policy_updates_total,result=accepted":     1,
		"fleetguard_agent_policy_updates_total,result=invalid":      1,
		"fleetguard_agent_policy_updates_total,result=scope_denied": 1,
		"fleetguard_agent_active_decisions,origin=central":          1,
		"fleetguard_agent_enforced_decisions":                       1,
		"fleetguard_agent_simulated":                                1,
		"fleetguard_agent_enforcement_healthy":                      0, // observe never claims enforcement
	})
	for _, secret := range []string{"203.0.113", "10.5.6.7", "lab-node-a", "lab-ssh", "d1"} {
		if strings.Contains(body, secret) {
			t.Fatalf("metrics leaked %q", secret)
		}
	}

	*now = now.Add(time.Minute) // > 3 poll intervals without contact
	_, stale := scrape(t, c)
	expect(t, stale, map[string]float64{"fleetguard_agent_controller_connected": 0})
}

func TestMetricsEnforceModeBackendFailureIsVisible(t *testing.T) {
	e, _, now, priv, fake := fixture(t, "enforce")
	cfg := RuntimeConfig{Mode: "enforce", FirewallBackend: "firewalld", PollIntervalSeconds: 5, ReconcileIntervalSeconds: 1}
	c := NewCollector(cfg, e, nil)
	c.now = func() time.Time { return *now }
	if _, err := e.Accept(context.Background(), snapshot(t, priv, *now, 1, "203.0.113.42/32")); err != nil {
		t.Fatal(err)
	}
	_, ok := scrape(t, c)
	expect(t, ok, map[string]float64{"fleetguard_agent_enforcement_healthy": 1, "fleetguard_agent_enforced_decisions": 1})

	fake.fail = true
	_ = e.Tick(context.Background())
	_, failed := scrape(t, c)
	expect(t, failed, map[string]float64{
		"fleetguard_agent_enforcement_healthy":             0,
		"fleetguard_agent_last_error":                      1,
		"fleetguard_agent_firewall_reconcile_errors_total": 1,
	})

	fake.fail = false
	_ = e.Tick(context.Background())
	*now = now.Add(10 * time.Second) // reconcile now stale (> 3 intervals)
	_, stale := scrape(t, c)
	expect(t, stale, map[string]float64{"fleetguard_agent_enforcement_healthy": 0})
}
