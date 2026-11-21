package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
	"github.com/maestroi/Fleetguard/internal/firewall/mock"
	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type memoryStore struct {
	state DurableState
	saves int
	fail  bool
}

func (s *memoryStore) Load() (DurableState, error) { return s.state, nil }
func (s *memoryStore) Save(v DurableState) error {
	if s.fail {
		return errors.New("disk full")
	}
	s.saves++
	s.state = v
	return nil
}

type realFake struct {
	applied []protocol.Decision
	removed int
	fail    bool
}

func (f *realFake) Capabilities(context.Context) (firewall.Capabilities, error) {
	return firewall.Capabilities{IPv4: true, ScopedPorts: true}, nil
}
func (f *realFake) Reconcile(_ context.Context, in []protocol.Decision) (firewall.AppliedState, error) {
	if f.fail {
		return firewall.AppliedState{}, errors.New("D-Bus unavailable")
	}
	f.applied = append([]protocol.Decision{}, in...)
	return firewall.AppliedState{ObservedAt: time.Now(), Decisions: f.applied}, nil
}
func (f *realFake) Inspect(_ context.Context) (firewall.AppliedState, error) {
	return firewall.AppliedState{Decisions: f.applied}, nil
}
func (f *realFake) RemoveOwned(context.Context) error { f.removed++; f.applied = nil; return nil }
func fixture(t *testing.T, mode string) (*Engine, *memoryStore, *time.Time, ed25519.PrivateKey, *realFake) {
	t.Helper()
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	policy := safety.Policy{
		Mode: mode, ProtectedCIDRs: []string{"10.0.0.0/8", "192.0.2.5/32"},
		ControllerIPs:         []string{"198.51.100.2"},
		ServiceScopes:         []safety.ServiceScope{{ServiceGroup: "lab-ssh", Service: "ssh", Transport: protocol.TransportTCP, Ports: []uint16{2222}}},
		MaxDecisionTTLSeconds: 120, MaxDecisions: 64,
	}
	var backend firewall.Backend
	fake := &realFake{}
	if mode == "observe" {
		var err error
		backend, err = mock.New(func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
	} else {
		backend = fake
	}
	store := &memoryStore{state: DurableState{Version: 1}}
	opts := EngineOptions{
		Audience: protocol.Audience{NodeID: "lab-node-a", ServiceGroup: "lab-ssh"},
		Keys:     map[string]ed25519.PublicKey{"lab-key": priv.Public().(ed25519.PublicKey)},
		Policy:   policy, Backend: backend, Store: store, Mode: mode, Now: func() time.Time { return now },
		MaxOfflineAge: 90 * time.Second, EmergencyDisabled: func() (bool, error) { return false, nil },
	}
	if mode == "observe" {
		opts.BackendName = "simulated"
	} else {
		opts.BackendName = "firewalld"
		opts.HostINPUTVerified = true
	}
	e, err := NewEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	return e, store, &now, priv, fake
}
func snapshot(t *testing.T, priv ed25519.PrivateKey, now time.Time, revision uint64, source string) protocol.SignedSnapshot {
	t.Helper()
	decisions := []protocol.Decision{}
	if source != "" {
		decisions = append(decisions, protocol.Decision{
			ID: "d1", Source: source, Action: protocol.ActionDrop, Service: "ssh", Transport: protocol.TransportTCP,
			DestinationPorts: []uint16{2222}, ExpiresAt: now.Add(50 * time.Second), ReasonCode: "verified_multi_node_abuse",
		})
	}
	signed, err := protocol.SignSnapshot(protocol.Snapshot{
		Schema: protocol.SchemaVersion, Revision: revision, IssuedAt: now, ExpiresAt: now.Add(110 * time.Second),
		Audience:  protocol.Audience{ServiceGroup: "lab-ssh", NodeID: "lab-node-a"},
		Decisions: decisions, KeyID: "lab-key",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
func TestAcceptPersistenceReplayAndInvalidSource(t *testing.T) {
	e, store, now, priv, _ := fixture(t, "observe")
	valid := snapshot(t, priv, *now, 1, "203.0.113.42/32")
	ack, err := e.Accept(context.Background(), valid)
	if err != nil || ack.State != protocol.StateValidated || store.state.Revision != 1 {
		t.Fatalf("initial accept: %+v %v", ack, err)
	}
	if store.saves != 1 {
		t.Fatal("expected persist-before-apply")
	}
	ack, err = e.Accept(context.Background(), valid)
	if err != nil || ack.Revision != 1 || store.saves != 1 {
		t.Fatal("identical controller re-poll must be idempotent")
	}
	corrupted := valid
	corrupted.SignatureBase64 = valid.PayloadBase64
	if _, err := e.Accept(context.Background(), corrupted); err == nil {
		t.Fatal("forged signature accepted")
	}
	forbidden := snapshot(t, priv, *now, 2, "10.5.6.7/32")
	rejected, err := e.Accept(context.Background(), forbidden)
	if err == nil || rejected.State != protocol.StateRejected || rejected.Reason != protocol.ReasonScopeMismatch {
		t.Fatal("protected CIDR not rejected")
	}
	next := snapshot(t, priv, *now, 2, "203.0.113.43/32")
	if _, err := e.Accept(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Accept(context.Background(), valid); err == nil {
		t.Fatal("rollback/replay accepted")
	}
	if store.state.Revision != 2 || store.saves != 2 || !reflect.DeepEqual(*store.state.Signed, next) {
		t.Fatal("invalid message replaced last good signed state")
	}
}
func TestRecoverAndOfflineTTL(t *testing.T) {
	e, store, now, priv, _ := fixture(t, "observe")
	signed := snapshot(t, priv, *now, 1, "203.0.113.42/32")
	if _, err := e.Accept(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	*now = (*now).Add(40 * time.Second)
	restarted, err := NewEngine(e.options)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.persisted.Revision != 1 {
		t.Fatal("lost monotonic watermark")
	}
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted.Status().ActiveDecisions != 1 {
		t.Fatal("valid decision did not recover")
	}
	*now = (*now).Add(11 * time.Second)
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted.Status().ActiveDecisions != 0 {
		t.Fatal("expired decision recreated after restart")
	}
	if _, err := restarted.Accept(context.Background(), signed); err != nil {
		t.Fatal("identical signed snapshot can be retried before snapshot TTL: ", err)
	}
	*now = (*now).Add(40 * time.Second)
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !restarted.Status().OfflineExpired || restarted.Status().ActiveDecisions != 0 {
		t.Fatal("offline age did not expire active state")
	}
	if store.state.Revision != 1 {
		t.Fatal("expiry must preserve replay watermark")
	}
	after, err := NewEngine(e.options)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status().Revision != 1 || !after.Status().OfflineExpired {
		t.Fatal("offline restart should preserve watermark and expire state")
	}
	if _, err := after.Accept(context.Background(), signed); err == nil {
		t.Fatal("offline stale snapshot reaccepted")
	}
}
func TestEnforceEmergencyAndFirewalldReload(t *testing.T) {
	e, _, now, priv, fake := fixture(t, "enforce")
	signed := snapshot(t, priv, *now, 1, "203.0.113.42/32")
	ack, err := e.Accept(context.Background(), signed)
	if err != nil || ack.State != protocol.StateApplied {
		t.Fatalf("apply: %+v %v", ack, err)
	}
	if len(fake.applied) != 1 {
		t.Fatal("backend did not apply")
	}
	fake.applied = nil // firewalld --reload clears owned runtime entries
	if err := e.Tick(context.Background()); err != nil || len(fake.applied) != 1 {
		t.Fatal("firewalld reload not reconciled", err)
	}
	e.options.EmergencyDisabled = func() (bool, error) { return true, nil }
	if err := e.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.applied) != 0 || fake.removed == 0 || !e.Status().Disabled {
		t.Fatal("emergency latch did not remove owned entries")
	}
	if _, err := e.Accept(context.Background(), snapshot(t, priv, *now, 2, "203.0.113.43/32")); err == nil {
		t.Fatal("emergency latch accepted new ban")
	}
	e.options.EmergencyDisabled = func() (bool, error) { return false, errors.New("untrusted latch path") }
	if err := e.Tick(context.Background()); err == nil || len(fake.applied) > 0 {
		t.Fatal("unsafe latch error must never enforce")
	}
	e.options.EmergencyDisabled = func() (bool, error) { return false, nil }
	if err := e.Tick(context.Background()); err != nil || len(fake.applied) != 1 {
		t.Fatal("restored local operator gate did not reconcile", err)
	}
	*now = (*now).Add(51 * time.Second)
	if err := e.Tick(context.Background()); err != nil || len(fake.applied) != 0 {
		t.Fatal("expired real ban not removed", err)
	}
}
func TestLocalProofAndFailurePaths(t *testing.T) {
	e, s, now, _, fake := fixture(t, "enforce")
	d := protocol.Decision{ID: "proof1", Source: "203.0.113.45/32", Action: protocol.ActionDrop, Service: "ssh", Transport: protocol.TransportTCP, DestinationPorts: []uint16{2222}, ExpiresAt: now.Add(30 * time.Second), ReasonCode: "verified_local_abuse"}
	if err := e.AddLocal(context.Background(), d, protocol.ProofUnverifiedLog); err == nil {
		t.Fatal("spoofable logs promoted to local ban")
	}
	if err := e.AddLocal(context.Background(), d, protocol.ProofEstablishedConnection); err != nil {
		t.Fatal(err)
	}
	if len(fake.applied) != 1 || s.saves != 0 {
		t.Fatal("local ban must not persist or bypass backend")
	}
	unsafe := d
	unsafe.ID = "unsafe"
	unsafe.Source = "10.1.1.1/32"
	if err := e.AddLocal(context.Background(), unsafe, protocol.ProofApplicationVerified); err == nil {
		t.Fatal("local proof bypassed protected source")
	}
	*now = (*now).Add(31 * time.Second)
	if err := e.Tick(context.Background()); err != nil || len(fake.applied) != 0 {
		t.Fatal("local TTL did not remove block", err)
	}
	fresh := d
	fresh.ID = "later"
	fresh.ExpiresAt = (*now).Add(20 * time.Second)
	fake.fail = true
	if err := e.AddLocal(context.Background(), fresh, protocol.ProofApplicationVerified); err == nil {
		t.Fatal("D-Bus failure reported applied")
	}
	if len(e.PendingLocalIDs()) != 0 {
		t.Fatal("failed local apply left a pending unapproved decision")
	}
}
func TestStoreFailureDoesNotAcceptOrApply(t *testing.T) {
	e, s, now, priv, _ := fixture(t, "observe")
	s.fail = true
	if _, err := e.Accept(context.Background(), snapshot(t, priv, *now, 1, "203.0.113.47/32")); err == nil {
		t.Fatal("disk full accepted policy")
	}
	if e.Status().Revision != 0 || s.saves != 0 {
		t.Fatal("in-memory state advanced on failed store")
	}
}
func TestFileStorePrivateAtomicPersistence(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store := FileStore{Dir: dir}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	_, _, now, _, _ := fixture(t, "observe")
	state := DurableState{Version: 1, Revision: 1, Signed: &protocol.SignedSnapshot{}, AcceptedAt: *now}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.Revision != 1 {
		t.Fatal("load persisted state", err)
	}
	info, err := os.Stat(filepath.Join(dir, stateFilename))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state permissions incorrect", err)
	}
	if err := os.Chmod(filepath.Join(dir, stateFilename), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("accepted group/world accessible state file")
	}
	if err := os.Remove(filepath.Join(dir, stateFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, stateFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("followed state symlink")
	}
}
