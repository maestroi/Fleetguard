//go:build linux && cgo

package store

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestApprovedDecisionReplacesCachedSnapshotsUntilExpiry(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "private", "lab.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const group, signer = "lab-ssh", "lab-key"
	if _, _, err := db.Snapshot("agent-a", group, signer, key, now); err != nil {
		t.Fatal(err)
	}
	d := protocol.Decision{ID: "approved", Source: "172.29.50.13/32", Action: protocol.ActionDrop, Service: "ssh", Transport: "tcp", DestinationPorts: []uint16{22}, ExpiresAt: now.Add(time.Minute), ReasonCode: "verified_multi_node_abuse"}
	nodes := []string{"agent-a", "agent-b"}
	if err := db.PublishApprovedDecision(group, nodes, d, signer, key, now); err != nil {
		t.Fatal(err)
	}
	if err := db.PublishApprovedDecision(group, []string{"agent-c", "agent-a"}, d, signer, key, now); err == nil {
		t.Fatal("second approval replaced an active decision")
	}
	wire, revision, err := db.Snapshot("agent-c", group, signer, key, now)
	if err != nil || revision != 1 {
		t.Fatalf("conflicting approval partially published: revision = %d, err = %v", revision, err)
	}
	untouched, err := protocol.VerifySignedSnapshot(wire, map[string]ed25519.PublicKey{signer: public}, protocol.Audience{NodeID: "agent-c", ServiceGroup: group}, 0, now)
	if err != nil || len(untouched.Decisions) != 0 {
		t.Fatalf("conflicting approval reached an unrelated node: %+v, err = %v", untouched, err)
	}
	for _, node := range nodes {
		wire, rev, err := db.Snapshot(node, group, signer, key, now)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := protocol.VerifySignedSnapshot(wire, map[string]ed25519.PublicKey{signer: public}, protocol.Audience{NodeID: node, ServiceGroup: group}, 0, now)
		if err != nil || len(snap.Decisions) != 1 || snap.Decisions[0].ID != d.ID || !snap.ExpiresAt.Equal(d.ExpiresAt) {
			t.Fatalf("%s: snapshot = %+v, err = %v", node, snap, err)
		}
		if node == "agent-a" && rev != 2 {
			t.Fatalf("preexisting snapshot revision = %d, want 2", rev)
		}
		wire, next, err := db.Snapshot(node, group, signer, key, d.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		snap, err = protocol.VerifySignedSnapshot(wire, map[string]ed25519.PublicKey{signer: public}, protocol.Audience{NodeID: node, ServiceGroup: group}, rev, d.ExpiresAt)
		if err != nil || len(snap.Decisions) != 0 || next != rev+1 {
			t.Fatalf("%s: expired snapshot = %+v, err = %v", node, snap, err)
		}
	}
}
