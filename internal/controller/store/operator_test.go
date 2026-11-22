//go:build linux && cgo

package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func auditEvidence(id, node, source string, when time.Time) protocol.Evidence {
	return protocol.Evidence{
		Schema: protocol.SchemaVersion, EventID: id, DedupKey: id, NodeID: node, ObservedAt: when,
		WindowSeconds: 10, SourceIP: source, Service: "ssh", Transport: protocol.TransportTCP,
		DestinationPorts: []uint16{2222}, Observation: "denied_traffic", Attempts: 3, ProofLevel: protocol.ProofUnverifiedLog,
	}
}
func TestNodeAuditScopedAndSignedAckIsNotKernelProof(t *testing.T) {
	now := time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)
	db, err := Open(filepath.Join(t.TempDir(), "private", "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e1 := auditEvidence("event-a", "lab-a", "203.0.113.42", now)
	e2 := auditEvidence("event-b", "lab-b", "198.51.100.12", now)
	if _, err := db.Ingest(e1, "ssh", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Ingest(e2, "ssh", now); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", 32)))
	signed, rev, err := db.Snapshot("lab-a", "ssh", "local-test-key", priv, now)
	if err != nil {
		t.Fatal(err)
	}
	if rev != 1 || signed.PayloadBase64 == "" {
		t.Fatal("missing signed snapshot")
	}
	ack := protocol.Acknowledgement{Schema: 1, NodeID: "lab-a", Revision: 1, State: protocol.StateValidated}
	if _, err := db.Acknowledge("lab-a", "ssh", ack, now); err != nil {
		t.Fatal(err)
	}
	view, err := db.ReadNodeAudit("lab-a", "ssh", 32)
	if err != nil {
		t.Fatal(err)
	}
	if view.NodeID != "lab-a" || view.EvidenceCount != 1 || len(view.Evidence) != 1 || view.Evidence[0].SourceIP != "203.0.113.42" || view.Revision != 1 || view.SignedSnapshot == nil || view.SignedSnapshot.KeyID != "local-test-key" || len(view.Acknowledgements) != 1 || view.EnforcementProof != "unverified_agent_ack" {
		t.Fatalf("unexpected operator view %+v", view)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "token") || strings.Contains(string(raw), "private_key") {
		t.Fatalf("secret-looking data leaked: %s", raw)
	}
	foreign, err := db.ReadNodeAudit("lab-a", "rpc", 32)
	if err != nil || len(foreign.Evidence) != 0 || foreign.Revision != 0 {
		t.Fatalf("cross-group leakage: %+v %v", foreign, err)
	}
	other, err := db.ReadNodeAudit("lab-b", "ssh", 32)
	if err != nil || other.EvidenceCount != 1 || other.Evidence[0].SourceIP != "198.51.100.12" {
		t.Fatalf("cross-node leakage: %+v %v", other, err)
	}
	for _, n := range []int{0, -1, 33} {
		if _, err := db.ReadNodeAudit("lab-a", "ssh", n); err == nil {
			t.Fatalf("bad audit limit %d accepted", n)
		}
	}
}
func TestRetentionConfigAndExplicitSensitivePurge(t *testing.T) {
	now := time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC)
	db, err := Open(filepath.Join(t.TempDir(), "private", "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, hours := range []int{0, 25, -1} {
		if err := db.SetEvidenceRetention(hours); err == nil {
			t.Fatalf("accepted retention %d", hours)
		}
	}
	if err := db.SetEvidenceRetention(1); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * time.Hour)
	fresh := now.Add(-10 * time.Minute)
	if _, err := db.Ingest(auditEvidence("old", "lab-a", "203.0.113.3", old), "ssh", old); err != nil {
		t.Fatal(err)
	}
	if err := db.AuditCandidate("ssh", protocol.Decision{Source: "203.0.113.3/32", Service: "ssh", Transport: protocol.TransportTCP, DestinationPorts: []uint16{2222}}, "advisory", "unverified", old); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Ingest(auditEvidence("fresh", "lab-a", "203.0.113.4", fresh), "ssh", fresh); err != nil {
		t.Fatal(err)
	}
	purge, err := db.PurgeSensitive(now)
	if err != nil {
		t.Fatal(err)
	}
	if purge.EvidenceRemoved != 1 || purge.AuditRemoved < 1 {
		t.Fatalf("old source data not purged: %+v", purge)
	}
	view, err := db.ReadNodeAudit("lab-a", "ssh", 32)
	if err != nil {
		t.Fatal(err)
	}
	if view.EvidenceCount != 1 || view.Evidence[0].SourceIP != "203.0.113.4" {
		t.Fatalf("data beyond retention not removed: %+v", view)
	}
	purge, err = db.PurgeSensitive(now)
	if err != nil || purge.EvidenceRemoved != 0 || purge.AuditRemoved != 0 {
		t.Fatalf("purge not idempotent: %+v %v", purge, err)
	}
	// Ingest must apply configured retention even without an explicit purge.
	if _, err := db.Ingest(auditEvidence("new", "lab-a", "203.0.113.5", now), "ssh", now); err != nil {
		t.Fatal(err)
	}
	view, err = db.ReadNodeAudit("lab-a", "ssh", 32)
	if err != nil || view.EvidenceCount != 2 {
		t.Fatalf("fresh evidence unexpectedly lost: %+v %v", view, err)
	}
}

func TestControllerInspectionIsReadOnlyAndCannotInitializeDatabase(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "missing.sqlite")
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("inspection created a missing database")
	}
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := database.Ingest(auditEvidence("read-only", "node-a", "203.0.113.8", now), "ssh", now); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := reader.ReadNodeAudit("node-a", "ssh", 16)
	if err != nil || audit.EvidenceCount != 1 {
		t.Fatalf("read-only audit unavailable: %+v %v", audit, err)
	}
	if _, err := reader.PurgeSensitive(now.Add(48 * time.Hour)); err == nil {
		t.Fatal("read-only connection permitted DELETE")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only inspection modified SQLite database")
	}
}
