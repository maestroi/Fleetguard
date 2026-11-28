package api

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/agent"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/internal/firewall/mock"
	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// End to end: controller SQLite revision -> authenticated HTTPS distribution
// -> pinned-TLS agent transport -> independent signature verification ->
// durable agent state -> ETag 304 on repeat -> add-only update.
func TestNeverBanAgentRetrievalEndToEnd(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "private", "controller.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, policyKey, _ := ed25519.GenerateKey(nil)
	fleetPub, fleetKey, _ := ed25519.GenerateKey(nil)
	now := testTime
	s, ts := newTestServer(t, db, registryWithHashes(t), &now, policyKey)
	if err := s.ConfigureNeverBan("fleet", fleetPub); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateNeverBan([]protocol.Protection{{CIDR: "192.0.2.0/24", Category: protocol.ProtectionInfrastructure}}, false, "uid:1", "seed", "fleet", fleetKey, now, time.Hour); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := agent.NewTransport(agent.RuntimeConfig{NodeID: "lab-a", ServiceGroup: "ssh", ControllerURL: ts.URL, TLSCAFile: caPath}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, _ := mock.New(func() time.Time { return now })
	fs := agent.FileStore{Dir: stateDir}
	engine, err := agent.NewEngine(agent.EngineOptions{
		Audience: protocol.Audience{NodeID: "lab-a", ServiceGroup: "ssh"},
		Keys:     map[string]ed25519.PublicKey{"test-key": policyKey.Public().(ed25519.PublicKey)},
		Policy: safety.Policy{Mode: "observe", ProtectedCIDRs: []string{"10.0.0.0/8"}, ControllerIPs: []string{"198.51.100.2"},
			ServiceScopes:         []safety.ServiceScope{{ServiceGroup: "ssh", Service: "ssh", Transport: protocol.TransportTCP, Ports: []uint16{22}}},
			MaxDecisionTTLSeconds: 120, MaxDecisions: 64},
		Backend: backend, Store: fs, Mode: "observe", BackendName: "simulated", Now: func() time.Time { return now },
		NeverBanKeys: map[string]ed25519.PublicKey{"fleet": fleetPub}, NeverBanRequired: true, ProtectionStore: fs,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	env, etag, notModified, err := transport.FetchNeverBan(ctx, "")
	if err != nil || notModified || etag == "" {
		t.Fatalf("fetch: %v %v %q", err, notModified, etag)
	}
	if err := engine.AcceptNeverBan(ctx, env); err != nil {
		t.Fatal(err)
	}
	if st := engine.Status(); st.ProtectionRevision != 1 || !st.ProtectionFresh {
		t.Fatalf("not accepted: %+v", st)
	}
	if _, _, notModified, err := transport.FetchNeverBan(ctx, etag); err != nil || !notModified {
		t.Fatalf("expected 304 for retained document: %v %v", err, notModified)
	}
	// Add-only update propagates and is persisted for restart.
	if _, err := db.UpdateNeverBan([]protocol.Protection{{CIDR: "2001:db8::/48", Category: protocol.ProtectionPeers}}, false, "uid:1", "peer", "fleet", fleetKey, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	env, _, notModified, err = transport.FetchNeverBan(ctx, etag)
	if err != nil || notModified {
		t.Fatalf("changed document returned 304: %v", err)
	}
	if err := engine.AcceptNeverBan(ctx, env); err != nil {
		t.Fatal(err)
	}
	persisted, err := fs.LoadProtection()
	if err != nil || persisted.Revision != 2 {
		t.Fatalf("not persisted: %+v %v", persisted, err)
	}
}
