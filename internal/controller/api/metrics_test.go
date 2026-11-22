package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestControllerMetricsAreBoundedAndLeakFree(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := testTime
	s, ts := newTestServer(t, db, registryWithHashes(t), &now, priv)
	c := ts.Client()

	request(t, c, ts.URL+"/v1/health?group=ssh", "GET", "lab-a", "bad-token-abcdefghijklmnopqrstuvwxyz-0123456789", nil)
	request(t, c, ts.URL+"/v1/health?group=ssh", "GET", "lab-a", tokenA, nil)
	request(t, c, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, evidence("event-1"))
	bad := evidence("event-2")
	bad.Service = "rpc" // not permitted for group ssh
	request(t, c, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, bad)
	request(t, c, ts.URL+"/v1/no-such-path/203.0.113.9", "GET", "lab-a", tokenA, nil)

	if problems, err := testutil.GatherAndLint(s.MetricsRegistry()); err != nil || len(problems) != 0 {
		t.Fatalf("lint: %v %+v", err, problems)
	}
	rec := httptest.NewRecorder()
	metrics.Handler(s.MetricsRegistry()).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	for _, want := range []string{
		`fleetguard_controller_http_requests_total{code="401",route="GET /v1/health"} 1`,
		`fleetguard_controller_http_requests_total{code="200",route="GET /v1/health"} 1`,
		`fleetguard_controller_http_requests_total{code="200",route="POST /v1/evidence"} 1`,
		`fleetguard_controller_http_requests_total{code="404",route="unmatched"} 1`,
		`fleetguard_controller_events_rejected_total{reason="service_scope_mismatch"} 1`,
		`fleetguard_controller_storage_errors_total{operation="ingest"} 0`,
		`fleetguard_controller_enforcement_enabled 0`,
		`fleetguard_controller_registered_nodes 2`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	for _, secret := range []string{"lab-a", "203.0.113", tokenA, "event-1", `group=`} {
		if strings.Contains(text, secret) {
			t.Fatalf("metrics leaked %q", secret)
		}
	}
	rec = httptest.NewRecorder()
	metrics.Handler(s.MetricsRegistry()).ServeHTTP(rec, httptest.NewRequest("GET", "/v1/snapshot", nil))
	if rec.Code != 404 {
		t.Fatal("metrics listener must serve only /metrics")
	}
}
