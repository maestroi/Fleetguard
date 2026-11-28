//go:build linux && cgo

package store

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestNeverBanStoreHistoryAndRenewal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"fleet": pub}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	peer := protocol.Protection{CIDR: "192.0.2.0/24", Category: protocol.ProtectionPeers}
	partner := protocol.Protection{CIDR: "2001:db8::/48", Category: protocol.ProtectionPartners}
	if _, err := db.ReadNeverBanRevision(0, keys); !errors.Is(err, ErrNeverBanMissing) {
		t.Fatal("empty store did not report missing", err)
	}
	if _, err := db.UpdateNeverBan(nil, true, "uid:1", "renew", "fleet", key, now, time.Hour); !errors.Is(err, ErrNeverBanMissing) {
		t.Fatal("renew created an empty list", err)
	}
	first, err := db.UpdateNeverBan([]protocol.Protection{peer}, false, "uid:1", "peer inventory", "fleet", key, now, time.Hour)
	if err != nil || first.List.Revision != 1 || first.Actor != "uid:1" || first.Reason != "peer inventory" {
		t.Fatal(first, err)
	}
	if _, err := db.UpdateNeverBan([]protocol.Protection{peer}, false, "uid:1", "duplicate", "fleet", key, now, time.Hour); err == nil {
		t.Fatal("duplicate-only update accepted")
	}
	bad := protocol.Protection{CIDR: "0.0.0.0/0", Category: protocol.ProtectionPeers}
	if _, err := db.UpdateNeverBan([]protocol.Protection{partner, bad}, false, "uid:2", "invalid batch", "fleet", key, now, time.Hour); err == nil {
		t.Fatal("invalid batch accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now = now.Add(2 * time.Hour)
	second, err := db.UpdateNeverBan([]protocol.Protection{partner}, false, "uid:2", "partner network", "fleet", key, now, time.Hour)
	if err != nil || second.List.Revision != 2 || len(second.List.Entries) != 2 {
		t.Fatal(second, err)
	}
	added, err := NeverBanDiff(first.List, second.List)
	if err != nil || len(added) != 1 || added[0] != partner {
		t.Fatal(added, err)
	}
	third, err := db.UpdateNeverBan(nil, true, "uid:2", "refresh", "fleet", key, now.Add(time.Minute), time.Hour)
	if err != nil || third.List.Revision != 3 || len(third.List.Entries) != 2 {
		t.Fatal(third, err)
	}
	if _, err := db.PurgeSensitive(now.Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	history, err := reader.ReadNeverBanRevision(1, keys)
	if err != nil || history.Envelope != first.Envelope {
		t.Fatal("history did not survive retention purge", history, err)
	}
	latest, err := reader.ReadNeverBanRevision(0, keys)
	if err != nil || latest.Envelope != third.Envelope {
		t.Fatal(latest, err)
	}
	if _, err := reader.UpdateNeverBan(nil, true, "uid:2", "read-only", "fleet", key, now.Add(time.Hour), time.Hour); err == nil {
		t.Fatal("read-only DB allowed write")
	}
}

func TestNeverBanStoreRejectsSignerAndClockRollback(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "private", "controller.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry := protocol.Protection{CIDR: "198.51.100.1/32", Category: protocol.ProtectionEdge}
	if _, err := db.UpdateNeverBan([]protocol.Protection{entry}, false, "uid:1", "initial", "fleet", key, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateNeverBan(nil, true, "uid:1", "wrong signer", "fleet", other, now, time.Hour); err == nil {
		t.Fatal("wrong signer replaced prior revision")
	}
	if _, err := db.UpdateNeverBan(nil, true, "uid:1", "clock rollback", "fleet", key, now.Add(-time.Second), time.Hour); err == nil {
		t.Fatal("clock rollback accepted")
	}
	if _, err := db.UpdateNeverBan(nil, true, "uid:1", "bad\nreason", "fleet", key, now, time.Hour); err == nil {
		t.Fatal("control character accepted")
	}
	got, err := db.ReadNeverBanRevision(0, map[string]ed25519.PublicKey{"fleet": pub})
	if err != nil || got.List.Revision != 1 {
		t.Fatal(got, err)
	}
}
