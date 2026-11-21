//go:build linux && cgo

package store

import (
	"github.com/maestroi/Fleetguard/pkg/protocol"
	"path/filepath"
	"testing"
	"time"
)

func TestGroupEvidenceBoundedPersistenceAndAudit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "private", "evidence.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, group := range []string{"group-a", "group-a", "group-b"} {
		e := protocol.Evidence{Schema: 1, EventID: "id-" + string(rune('a'+i)), NodeID: "node-a", DedupKey: "key-" + string(rune('a'+i)), ObservedAt: now, WindowSeconds: 30, SourceIP: "203.0.113.42", Service: "service", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, Observation: "application_abuse", Attempts: 10, ProofLevel: protocol.ProofApplicationVerified}
		if _, err := db.Ingest(e, group, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.GroupEvidence("group-a", now.Add(-time.Minute), 2)
	if err != nil || len(rows) != 2 {
		t.Fatalf("isolation: %d %v", len(rows), err)
	}
	if _, err = db.GroupEvidence("group-a", now.Add(-time.Minute), 1); err == nil {
		t.Fatal("silent truncation accepted")
	}
	rows, err = db.GroupEvidence("group-b", now.Add(-time.Minute), 2)
	if err != nil || len(rows) != 1 {
		t.Fatalf("wrong group: %d %v", len(rows), err)
	}
	if err := db.AuditEvaluation("group-a", 0, "observe_only", now); err != nil {
		t.Fatal(err)
	}
	count, err := db.AuditCount()
	if err != nil || count != 4 {
		t.Fatalf("audit count: %d %v", count, err)
	}
}
