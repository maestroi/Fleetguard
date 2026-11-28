package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type memoryProtection struct {
	state ProtectionState
	saves int
}

func (m *memoryProtection) LoadProtection() (ProtectionState, error) {
	if m.state.Version == 0 {
		return ProtectionState{Version: 1}, nil
	}
	return m.state, nil
}
func (m *memoryProtection) SaveProtection(st ProtectionState) error {
	m.saves++
	m.state = st
	return nil
}

var fleetKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))

type nbEnv struct {
	e     *Engine
	opts  EngineOptions
	now   *time.Time
	priv  ed25519.PrivateKey
	fake  *realFake
	prot  *memoryProtection
	store *memoryStore
}

func nbFixture(t *testing.T, required bool) *nbEnv {
	t.Helper()
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	env := &nbEnv{now: &now, priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)), fake: &realFake{}, prot: &memoryProtection{}, store: &memoryStore{state: DurableState{Version: 1}}}
	env.opts = EngineOptions{
		Audience: protocol.Audience{NodeID: "lab-node-a", ServiceGroup: "lab-ssh"},
		Keys:     map[string]ed25519.PublicKey{"lab-key": env.priv.Public().(ed25519.PublicKey)},
		Policy: safety.Policy{Mode: "enforce", ProtectedCIDRs: []string{"10.0.0.0/8"}, ControllerIPs: []string{"198.51.100.2"},
			ServiceScopes:         []safety.ServiceScope{{ServiceGroup: "lab-ssh", Service: "ssh", Transport: protocol.TransportTCP, Ports: []uint16{2222}}},
			MaxDecisionTTLSeconds: 120, MaxDecisions: 64},
		Backend: env.fake, Store: env.store, Mode: "enforce", BackendName: "firewalld", HostINPUTVerified: true,
		Now: func() time.Time { return *env.now }, MaxOfflineAge: 90 * time.Second,
		EmergencyDisabled: func() (bool, error) { return false, nil },
		NeverBanKeys:      map[string]ed25519.PublicKey{"fleet": fleetKey.Public().(ed25519.PublicKey)},
		NeverBanRequired:  required, ProtectionStore: env.prot,
	}
	env.restart(t)
	return env
}

func (env *nbEnv) restart(t *testing.T) {
	t.Helper()
	e, err := NewEngine(env.opts)
	if err != nil {
		t.Fatal(err)
	}
	env.e = e
}

func signList(t *testing.T, key ed25519.PrivateKey, keyID string, revision uint64, issued time.Time, cidrs ...string) protocol.SignedNeverBanList {
	t.Helper()
	entries := []protocol.Protection{}
	for _, c := range cidrs {
		entries = append(entries, protocol.Protection{CIDR: c, Category: protocol.ProtectionPeers})
	}
	signed, err := protocol.SignNeverBanList(protocol.NeverBanList{Schema: protocol.SchemaVersion, Revision: revision,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), Entries: entries, KeyID: keyID}, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func multiSnapshot(t *testing.T, priv ed25519.PrivateKey, now time.Time, revision uint64, sources ...string) protocol.SignedSnapshot {
	t.Helper()
	decisions := []protocol.Decision{}
	for i, src := range sources {
		decisions = append(decisions, protocol.Decision{ID: "d" + string(rune('a'+i)), Source: src, Action: protocol.ActionDrop, Service: "ssh",
			Transport: protocol.TransportTCP, DestinationPorts: []uint16{2222}, ExpiresAt: now.Add(100 * time.Second), ReasonCode: "operator_incident"})
	}
	signed, err := protocol.SignSnapshot(protocol.Snapshot{Schema: protocol.SchemaVersion, Revision: revision, IssuedAt: now, ExpiresAt: now.Add(110 * time.Second),
		Audience: protocol.Audience{ServiceGroup: "lab-ssh", NodeID: "lab-node-a"}, Decisions: decisions, KeyID: "lab-key"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func appliedSources(f *realFake) map[string]bool {
	out := map[string]bool{}
	for _, d := range f.applied {
		out[d.Source] = true
	}
	return out
}

func TestNeverBanWithholdsProtectedEntriesWithPartialAck(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 1, *env.now, "192.0.2.0/24", "2001:db8::/48")); err != nil {
		t.Fatal(err)
	}
	ack, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 1, "192.0.2.9/32", "203.0.113.5/32"))
	if err != nil || ack.State != protocol.StatePartial || ack.Reason != protocol.ReasonProtectedSource {
		t.Fatalf("expected partial ack, got %+v %v", ack, err)
	}
	if err := protocol.ValidateAcknowledgement(ack); err != nil {
		t.Fatal(err)
	}
	got := appliedSources(env.fake)
	if got["192.0.2.9/32"] || !got["203.0.113.5/32"] {
		t.Fatalf("protected entry installed or eligible entry missing: %v", got)
	}
	st := env.e.Status()
	if st.ProtectedWithheld != 1 || st.RejectedProtectedSource != 1 || st.CentralDecisions != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestNeverBanUpdateRemovesActiveConflictingBanAndPreventsRestore(t *testing.T) {
	env := nbFixture(t, false)
	ctx := context.Background()
	if _, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 1, "203.0.113.5/32", "198.51.100.77/32")); err != nil {
		t.Fatal(err)
	}
	if !appliedSources(env.fake)["203.0.113.5/32"] {
		t.Fatal("setup: ban not installed")
	}
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 1, *env.now, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	got := appliedSources(env.fake)
	if got["203.0.113.5/32"] || !got["198.51.100.77/32"] {
		t.Fatalf("conflicting ban not removed immediately: %v", got)
	}
	for range 3 {
		*env.now = env.now.Add(5 * time.Second)
		if err := env.e.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if appliedSources(env.fake)["203.0.113.5/32"] {
		t.Fatal("protected ban restored on later reconcile")
	}
	if st := env.e.Status(); st.ProtectionRemovals != 1 || st.ProtectionCleanupFailures != 0 {
		t.Fatalf("removal accounting %+v", st)
	}
}

func TestNeverBanRejectsForgedReplayRemovalAndPolicySigner(t *testing.T) {
	env := nbFixture(t, false)
	ctx := context.Background()
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 2, *env.now, "192.0.2.0/24", "198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}
	saves := env.prot.saves
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 2, *env.now, "192.0.2.0/24", "198.51.100.0/24")); err != nil || env.prot.saves != saves {
		t.Fatal("identical repeat must be idempotent without rewrite")
	}
	cases := map[string]protocol.SignedNeverBanList{
		"replay":        signList(t, fleetKey, "fleet", 1, *env.now, "192.0.2.0/24", "198.51.100.0/24"),
		"removal":       signList(t, fleetKey, "fleet", 3, *env.now, "192.0.2.0/24"),
		"policy signer": signList(t, env.priv, "lab-key", 3, *env.now, "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"),
		"expired":       signList(t, fleetKey, "fleet", 3, env.now.Add(-2*time.Hour), "192.0.2.0/24", "198.51.100.0/24"),
	}
	forged := signList(t, fleetKey, "fleet", 3, *env.now, "192.0.2.0/24", "198.51.100.0/24")
	forged.SignatureBase64 = cases["replay"].SignatureBase64
	cases["forged"] = forged
	for name, envelope := range cases {
		if err := env.e.AcceptNeverBan(ctx, envelope); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if st := env.e.Status(); st.ProtectionRevision != 2 || st.ProtectionEntries != 2 || env.prot.saves != saves {
		t.Fatalf("rejected update changed state: %+v", st)
	}
	// Signer separation is enforced at construction too.
	opts := env.opts
	opts.NeverBanKeys = map[string]ed25519.PublicKey{"other": env.priv.Public().(ed25519.PublicKey)}
	if _, err := NewEngine(opts); err == nil {
		t.Fatal("policy key accepted as never-ban trust anchor")
	}
	opts.NeverBanKeys = nil
	opts.NeverBanRequired = true
	if _, err := NewEngine(opts); err == nil {
		t.Fatal("required protection without trust anchor accepted")
	}
}

func TestNeverBanRequiredMissingRefusesNewBans(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	ack, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 1, "203.0.113.5/32"))
	if err == nil || ack.State != protocol.StateRejected || ack.Reason != protocol.ReasonProtectionStale {
		t.Fatalf("ban accepted without fleet protection: %+v %v", ack, err)
	}
	if len(env.fake.applied) != 0 {
		t.Fatal("ban installed without protection")
	}
	// An empty (unban-all) snapshot is still accepted.
	if ack, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 2)); err != nil || ack.State != protocol.StateApplied {
		t.Fatalf("removal-only snapshot refused: %+v %v", ack, err)
	}
	if err := env.e.AddLocal(ctx, protocol.Decision{ID: "x", Source: "203.0.113.6/32", Action: protocol.ActionDrop, Service: "ssh", Transport: protocol.TransportTCP,
		DestinationPorts: []uint16{2222}, ExpiresAt: env.now.Add(time.Minute), ReasonCode: "local"}, protocol.ProofApplicationVerified); err == nil {
		t.Fatal("local ban accepted without fleet protection")
	}
}

// resign re-issues base's exact decisions under a new revision and lease.
func resign(t *testing.T, priv ed25519.PrivateKey, base protocol.SignedSnapshot, baseIssued time.Time, revision uint64, issued time.Time) protocol.SignedSnapshot {
	t.Helper()
	keys := map[string]ed25519.PublicKey{"lab-key": priv.Public().(ed25519.PublicKey)}
	snap, err := protocol.VerifySignedSnapshot(base, keys, protocol.Audience{ServiceGroup: "lab-ssh", NodeID: "lab-node-a"}, 0, baseIssued)
	if err != nil {
		t.Fatal(err)
	}
	snap.Revision, snap.IssuedAt, snap.ExpiresAt = revision, issued, issued.Add(110*time.Second)
	signed, err := protocol.SignSnapshot(snap, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Required list goes stale: lease renewals of EXISTING bans are accepted
// during one MaxOfflineAge grace, new bans are refused, and after the grace
// every ban lapses even though the snapshot lease itself is still valid.
func TestNeverBanStaleExistingBansLapseAfterGrace(t *testing.T) {
	env := nbFixture(t, true)
	env.opts.MaxOfflineAge = 30 * time.Second
	env.restart(t)
	ctx := context.Background()
	start := *env.now
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 1, start.Add(-59*time.Minute), "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	base := multiSnapshot(t, env.priv, start, 1, "203.0.113.5/32", "203.0.113.6/32")
	if _, err := env.e.Accept(ctx, base); err != nil {
		t.Fatal(err)
	}
	for i, offset := range []time.Duration{25 * time.Second, 50 * time.Second, 70 * time.Second} {
		*env.now = start.Add(offset)
		ack, err := env.e.Accept(ctx, resign(t, env.priv, base, start, uint64(i+2), *env.now))
		if err != nil || ack.State != protocol.StateApplied || len(env.fake.applied) != 2 {
			t.Fatalf("renewal at %v: %+v %v applied=%d", offset, ack, err, len(env.fake.applied))
		}
	}
	if !env.e.Status().ProtectionStale {
		t.Fatal("list expired at +60s but not reported stale")
	}
	added := multiSnapshot(t, env.priv, *env.now, 9, "203.0.113.7/32")
	if ack, _ := env.e.Accept(ctx, added); ack.Reason != protocol.ReasonProtectionStale {
		t.Fatalf("new ban accepted while stale: %+v", ack)
	}
	*env.now = start.Add(91 * time.Second) // list expiry (+60s) + grace (30s)
	if err := env.e.Tick(ctx); err != nil || len(env.fake.applied) != 0 {
		t.Fatalf("bans survived stale grace: %v %v", err, env.fake.applied)
	}
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 2, *env.now, "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	if ack, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 10, "203.0.113.8/32")); err != nil || ack.State != protocol.StateApplied {
		t.Fatalf("fresh list should re-enable bans: %+v %v", ack, err)
	}
}

func TestNeverBanSurvivesRestartAndSignerRotation(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 4, *env.now, "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	env.restart(t)
	if st := env.e.Status(); st.ProtectionRevision != 4 || st.ProtectionUnverified {
		t.Fatalf("restart lost protection: %+v", st)
	}
	// Rotate the trust anchor away: entries retained but not fresh.
	rotated := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	env.opts.NeverBanKeys = map[string]ed25519.PublicKey{"fleet-2": rotated.Public().(ed25519.PublicKey)}
	env.restart(t)
	st := env.e.Status()
	if st.ProtectionRevision != 4 || !st.ProtectionUnverified || st.ProtectionEntries != 1 {
		t.Fatalf("rotation dropped protections: %+v", st)
	}
	// The new signer may not roll back revision or drop retained entries.
	if err := env.e.AcceptNeverBan(ctx, signList(t, rotated, "fleet-2", 5, *env.now, "198.51.100.0/24")); err == nil {
		t.Fatal("rotated signer removed retained protection")
	}
	if err := env.e.AcceptNeverBan(ctx, signList(t, rotated, "fleet-2", 5, *env.now, "192.0.2.0/24", "198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}
}

func TestNeverBanFileStoreAtomicPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := FileStore{Dir: dir}
	if st, err := fs.LoadProtection(); err != nil || st.Revision != 0 {
		t.Fatalf("empty load %+v %v", st, err)
	}
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	signed := signList(t, fleetKey, "fleet", 1, now, "192.0.2.0/24")
	if err := fs.SaveProtection(ProtectionState{Version: 1, Revision: 1, Signed: &signed, AcceptedAt: now}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, neverBanFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file not private: %v %v", info, err)
	}
	if st, err := fs.LoadProtection(); err != nil || st.Revision != 1 || *st.Signed != signed {
		t.Fatalf("round trip %+v %v", st, err)
	}
	if err := fs.SaveProtection(ProtectionState{Version: 1, Revision: 1}); err == nil {
		t.Fatal("unsigned revision persisted")
	}
	if err := os.WriteFile(filepath.Join(dir, neverBanFilename), []byte(`{"version":1,"revision":1,"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.LoadProtection(); err == nil {
		t.Fatal("unknown fields accepted")
	}
}

type fakeNB struct {
	env       protocol.SignedNeverBanList
	err       error
	etagsSent []string
}

func (f *fakeNB) FetchNeverBan(_ context.Context, etag string) (protocol.SignedNeverBanList, string, bool, error) {
	f.etagsSent = append(f.etagsSent, etag)
	if f.err != nil {
		return protocol.SignedNeverBanList{}, "", false, f.err
	}
	if etag == `"v1"` {
		return protocol.SignedNeverBanList{}, etag, true, nil
	}
	return f.env, `"v1"`, false, nil
}

type fakePolicy struct {
	snap    protocol.SignedSnapshot
	fetches int
}

func (f *fakePolicy) Fetch(context.Context) (protocol.SignedSnapshot, error) {
	f.fetches++
	return f.snap, nil
}
func (f *fakePolicy) Acknowledge(context.Context, protocol.Acknowledgement) error { return nil }

func TestPollerNeverBanFailureDoesNotBlockSnapshotAndETagOnlyAfterAccept(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	nb := &fakeNB{err: context.DeadlineExceeded}
	policy := &fakePolicy{snap: multiSnapshot(t, env.priv, *env.now, 1)}
	p := &Poller{Engine: env.e, Client: policy, NeverBan: nb}
	if err := p.PollOnce(ctx); err == nil || policy.fetches != 1 {
		t.Fatalf("snapshot poll blocked by protection failure: %v fetches=%d", err, policy.fetches)
	}
	// Invalid document: no ETag retained.
	nb.err = nil
	nb.env = signList(t, env.priv, "lab-key", 1, *env.now, "192.0.2.0/24")
	if err := p.PollOnce(ctx); err == nil {
		t.Fatal("policy-signed list accepted")
	}
	nb.env = signList(t, fleetKey, "fleet", 1, *env.now, "192.0.2.0/24")
	if err := p.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"", "", "", `"v1"`}
	for i := range want {
		if nb.etagsSent[i] != want[i] {
			t.Fatalf("etags sent %q want %q", nb.etagsSent, want)
		}
	}
}

func TestNeverBanMetricsBoundedAndLintClean(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 3, *env.now, "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 1, "192.0.2.9/32", "203.0.113.5/32")); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(RuntimeConfig{Mode: "enforce", FirewallBackend: "firewalld", PollIntervalSeconds: 5, ReconcileIntervalSeconds: 5,
		NeverBanKeysFile: "/etc/fleetguard/never-ban.json", NeverBanRequired: true}, env.e, nil)
	c.now = func() time.Time { return *env.now }
	body, got := scrape(t, c)
	expect(t, got, map[string]float64{
		"fleetguard_agent_protection_required":                                    1,
		"fleetguard_agent_protection_revision":                                    3,
		"fleetguard_agent_protection_entries":                                     1,
		"fleetguard_agent_protection_fresh":                                       1,
		"fleetguard_agent_protection_withheld_decisions":                          1,
		"fleetguard_agent_protection_updates_total,result=accepted":               1,
		"fleetguard_agent_decisions_rejected_total,reason=protected_source":       1,
		"fleetguard_agent_protection_rejections_by_category_total,category=peers": 1,
		"fleetguard_agent_protection_rejections_by_category_total,category=edge":  0,
	})
	for _, leak := range []string{"192.0.2", "203.0.113"} {
		if strings.Contains(body, leak) {
			t.Fatalf("metrics leaked address %s", leak)
		}
	}
}

// #41 acceptance: the fleet list never removes or narrows a local protection.
// 10.0.0.0/8 is only in the root-owned local policy, not in the fleet list.
func TestFleetListNeverRemovesLocalProtection(t *testing.T) {
	env := nbFixture(t, true)
	ctx := context.Background()
	if err := env.e.AcceptNeverBan(ctx, signList(t, fleetKey, "fleet", 1, *env.now, "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	ack, err := env.e.Accept(ctx, multiSnapshot(t, env.priv, *env.now, 1, "10.5.6.7/32"))
	if err == nil || ack.State != protocol.StateRejected || ack.Reason != protocol.ReasonScopeMismatch {
		t.Fatalf("locally protected source accepted with fleet list present: %+v %v", ack, err)
	}
	if len(env.fake.applied) != 0 {
		t.Fatal("locally protected ban installed")
	}
}
