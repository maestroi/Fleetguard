package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const tokenA = "node-a-lab-token-abcdefghijklmnopqrstuvwxyz-0123456789"
const tokenB = "node-b-lab-token-abcdefghijklmnopqrstuvwxyz-0123456789"

var testTime = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func sha(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func fixtures() auth.Registry {
	return auth.Registry{Nodes: []auth.Node{{NodeID: "lab-a", TokenSHA256: sha(tokenA), Groups: []string{"ssh"}}, {NodeID: "lab-b", TokenSHA256: sha(tokenB), Groups: []string{"ssh", "rpc"}}}, Groups: map[string]auth.Group{"ssh": {Services: []string{"ssh"}}, "rpc": {Services: []string{"rpc"}}}}
}

// registryWithHashes uses the exact loader to populate constant-time binary hashes.
func registryWithHashes(t *testing.T) auth.Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	data, _ := json.Marshal(fixtures())
	if err := writeSecret(path, data); err != nil {
		t.Fatal(err)
	}
	r, err := auth.LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func writeSecret(path string, b []byte) error { return osWriteFile(path, b) }
func osWriteFile(path string, b []byte) error { return os.WriteFile(path, b, 0600) }
func newTestServer(t *testing.T, db *store.DB, registry auth.Registry, clock *time.Time, priv ed25519.PrivateKey) (*Server, *httptest.Server) {
	t.Helper()
	s := New(registry, db, "test-key", priv, func() time.Time { return *clock }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go s.RunWriter(ctx.Done())
	t.Cleanup(cancel)
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}
func request(t *testing.T, client *http.Client, url, method, node, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Fleetguard-Node-ID", node)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}
func evidence(id string) protocol.Evidence {
	return protocol.Evidence{Schema: 1, EventID: id, NodeID: "lab-a", DedupKey: id, ObservedAt: testTime, WindowSeconds: 30, SourceIP: "203.0.113.42", Service: "ssh", Transport: protocol.TransportTCP, DestinationPorts: []uint16{22}, Observation: "denied_connections", Attempts: 10, ProofLevel: protocol.ProofUnverifiedLog}
}

func TestTLSAuthScopesIngestionSnapshotAckAndRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "events.sqlite")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry := registryWithHashes(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime
	s, ts := newTestServer(t, db, registry, &now, priv)
	client := ts.Client()
	for _, tt := range []struct {
		node, token, group string
		status             int
	}{
		{"lab-a", "wrong-token-value-abcdefghijklmnopqrstuvwxyz-0123456789", "ssh", 401},
		{"lab-b", tokenA, "ssh", 401},
		{"lab-a", tokenA, "rpc", 403},
		{"lab-b", tokenB, "rpc", 200},
	} {
		status, _ := request(t, client, ts.URL+"/v1/health?group="+tt.group, "GET", tt.node, tt.token, nil)
		if status != tt.status {
			t.Fatalf("health node=%s group=%s status=%d want %d", tt.node, tt.group, status, tt.status)
		}
	}
	e := evidence("event-1")
	for i := 0; i < 2; i++ {
		status, b := request(t, client, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, e)
		if status != 200 || !strings.Contains(string(b), fmt.Sprintf(`"duplicate":%v`, i == 1)) {
			t.Fatalf("ingest %d: %d %s", i, status, b)
		}
	}
	count, err := db.EventCount()
	if err != nil || count != 1 {
		t.Fatalf("dedup count=%d err=%v", count, err)
	}
	other := evidence("event-1")
	other.Attempts = 15
	status, _ := request(t, client, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, other)
	if status != 409 {
		t.Fatalf("conflicting event: %d", status)
	}
	spoof := evidence("spoof")
	spoof.NodeID = "lab-b"
	status, _ = request(t, client, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, spoof)
	if status != 422 {
		t.Fatalf("spoof evidence: %d", status)
	}
	outOfScope := evidence("wrong-service")
	outOfScope.Service = "rpc"
	status, _ = request(t, client, ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, outOfScope)
	if status != 403 {
		t.Fatalf("service mismatch: %d", status)
	}
	status, b := request(t, client, ts.URL+"/v1/snapshot?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 200 {
		t.Fatalf("snapshot %d %s", status, b)
	}
	snapshotWire := append([]byte(nil), b...)
	signed, err := protocol.DecodeSignedSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := protocol.VerifySignedSnapshot(signed, map[string]ed25519.PublicKey{"test-key": pub}, protocol.Audience{ServiceGroup: "ssh", NodeID: "lab-a"}, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || len(snapshot.Decisions) != 0 {
		t.Fatalf("unexpected decisions: %#v", snapshot)
	}
	status, b2 := request(t, client, ts.URL+"/v1/snapshot?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 200 || !bytes.Equal(b, b2) {
		t.Fatalf("retry mutated snapshot: %d %s", status, b2)
	}
	status, _ = request(t, client, ts.URL+"/v1/snapshot?group=ssh", "GET", "lab-b", tokenB, nil)
	if status != 200 {
		t.Fatalf("node B snapshot %d", status)
	}
	ack := protocol.Acknowledgement{Schema: 1, NodeID: "lab-a", Revision: 1, State: protocol.StateValidated}
	for i := 0; i < 2; i++ {
		status, b = request(t, client, ts.URL+"/v1/ack?group=ssh", "POST", "lab-a", tokenA, ack)
		if status != 200 || !strings.Contains(string(b), fmt.Sprintf(`"duplicate":%v`, i == 1)) {
			t.Fatalf("ack %d: %d %s", i, status, b)
		}
	}
	ack.Revision = 2
	status, _ = request(t, client, ts.URL+"/v1/ack?group=ssh", "POST", "lab-a", tokenA, ack)
	if status != 409 {
		t.Fatalf("unpublished ack %d", status)
	}
	// Registry update takes effect immediately and is audited, no HTTP admin endpoint.
	updated := registryWithHashes(t)
	updated.Nodes[0].Revoked = true
	if err := s.ReplaceRegistry(updated); err != nil {
		t.Fatal(err)
	}
	status, _ = request(t, client, ts.URL+"/v1/snapshot?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 401 {
		t.Fatalf("revocation %d", status)
	}
	if n, err := db.AuditCount(); err != nil || n < 3 {
		t.Fatalf("audit entries %d %v", n, err)
	}
	// Restart retains all events and exactly the same policy revision/envelope.
	ts.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	_, ts2 := newTestServer(t, db2, registry, &now, priv)
	status, b2 = request(t, ts2.Client(), ts2.URL+"/v1/snapshot?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 200 || !bytes.Equal(snapshotWire, b2) {
		t.Fatalf("policy changed after restart: %d %s", status, b2)
	}
	now = now.Add(3 * time.Minute)
	status, b2 = request(t, ts2.Client(), ts2.URL+"/v1/snapshot?group=ssh", "GET", "lab-a", tokenA, nil)
	if status != 200 {
		t.Fatalf("rotated snapshot %d %s", status, b2)
	}
	signed, err = protocol.DecodeSignedSnapshot(b2)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = protocol.VerifySignedSnapshot(signed, map[string]ed25519.PublicKey{"test-key": pub}, protocol.Audience{ServiceGroup: "ssh", NodeID: "lab-a"}, 1, now)
	if err != nil || snapshot.Revision != 2 {
		t.Fatalf("revision after TTL: %v %#v", err, snapshot)
	}
	count, err = db2.EventCount()
	if err != nil || count != 1 {
		t.Fatalf("persistent count %d %v", count, err)
	}
}

func TestBodyBoundsRateLimitingAndTLSRequired(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "evidence.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime
	_, ts := newTestServer(t, db, registryWithHashes(t), &now, key)
	for i := 0; i < 33; i++ {
		ev := evidence(fmt.Sprintf("burst-%d", i))
		status, _ := request(t, ts.Client(), ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, ev)
		expected := 200
		if i == 32 {
			expected = 429
		}
		if status != expected {
			t.Fatalf("burst #%d got %d want %d", i, status, expected)
		}
	}
	now = now.Add(time.Second)
	status, _ := request(t, ts.Client(), ts.URL+"/v1/evidence?group=ssh", "POST", "lab-a", tokenA, evidence("refilled"))
	if status != 200 {
		t.Fatalf("not refilled: %d", status)
	}
	// Plain HTTP is never accepted, even for an otherwise valid credential.
	plain := httptest.NewServer(newFakeHandler(t, db, key))
	defer plain.Close()
	status, _ = request(t, plain.Client(), plain.URL+"/v1/health", "GET", "lab-a", tokenA, nil)
	if status != 426 {
		t.Fatalf("plaintext accepted: %d", status)
	}
	req, err := http.NewRequest("POST", ts.URL+"/v1/ack?group=ssh", strings.NewReader(`{"schema":1,"node_id":"lab-a","node_id":"lab-b","revision":1,"state":"received"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fleetguard-Node-ID", "lab-a")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("duplicate JSON member accepted: %d", resp.StatusCode)
	}
}
func newFakeHandler(t *testing.T, db *store.DB, key ed25519.PrivateKey) http.Handler {
	t.Helper()
	s := New(registryWithHashes(t), db, "test-key", key, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s.Handler()
}
