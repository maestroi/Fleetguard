package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maestroi/Fleetguard/internal/controller/store"
)

func TestAuthenticatedOperatorAuditScopeAndHealthDoesNotLeakSecrets(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "private", "node-audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry := registryWithHashes(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime
	_, server := newTestServer(t, db, registry, &now, priv)
	client := server.Client()
	event := evidence("audit-event-a")
	status, body := request(t, client, server.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, event)
	if status != 200 {
		t.Fatalf("evidence ingest failed %d %s", status, body)
	}
	for _, tc := range []struct {
		node, token, group string
		want               int
	}{
		{"lab-a", tokenA, "ssh", 200},
		{"lab-a", tokenA, "rpc", 403},
		{"lab-b", tokenB, "ssh", 200},
		{"lab-b", tokenA, "ssh", 401},
		{"unknown", tokenA, "ssh", 401},
	} {
		status, body = request(t, client, server.URL+"/v1/audit?group="+tc.group+"&limit=16", "GET", tc.node, tc.token, nil)
		if status != tc.want {
			t.Fatalf("node %s group %s: got %d expected %d: %s", tc.node, tc.group, status, tc.want, body)
		}
		if status == 200 {
			var view store.NodeAudit
			if err := json.Unmarshal(body, &view); err != nil {
				t.Fatal(err)
			}
			if view.NodeID != tc.node || view.ServiceGroup != tc.group {
				t.Fatal("wrong audit scope", view)
			}
			if tc.node == "lab-a" && (view.EvidenceCount != 1 || len(view.Evidence) != 1) {
				t.Fatalf("own evidence missing %+v", view)
			}
			if tc.node == "lab-b" && (view.EvidenceCount != 0 || len(view.Evidence) != 0) {
				t.Fatalf("foreign evidence disclosed %+v", view)
			}
			if strings.Contains(string(body), tokenA) || strings.Contains(string(body), tokenB) || strings.Contains(string(body), "signing_key") {
				t.Fatalf("credential leaked: %s", body)
			}
		}
	}
	status, _ = request(t, client, server.URL+"/v1/audit?group=ssh&limit=999", "GET", "lab-a", tokenA, nil)
	if status != 400 {
		t.Fatalf("unbounded view accepted: %d", status)
	}
	status, body = request(t, client, server.URL+"/v1/health?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 200 || !strings.Contains(string(body), `"enforcement_enabled":false`) || !strings.Contains(string(body), `"applied_state_verified":false`) {
		t.Fatalf("health falsely claims applied state: %d %s", status, body)
	}
	if strings.Contains(string(body), tokenA) || strings.Contains(string(body), tokenB) {
		t.Fatal("health credential leak")
	}
	// No separate unauthenticated listener or hidden all-fleet view.
	status, _ = request(t, client, server.URL+"/v1/audit?group=ssh", "GET", "lab-a", "wrong-token", nil)
	if status != 401 {
		t.Fatalf("unauthenticated operator API exposed: %d", status)
	}
	_ = os.ErrNotExist
}
