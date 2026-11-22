package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func operatorFixture(t *testing.T) (string, FileStore, time.Time, ed25519.PrivateKey) {
	t.Helper()
	_, _, now, priv, _ := fixture(t, "observe")
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys.json")
	safetyFile := filepath.Join(dir, "safety.json")
	configPath := filepath.Join(dir, "runtime.json")
	keyData, _ := json.Marshal(map[string]string{"lab-key": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))})
	if err := os.WriteFile(keys, keyData, 0600); err != nil {
		t.Fatal(err)
	}
	policy := safety.Policy{
		Mode:                  "observe",
		ProtectedCIDRs:        []string{"10.0.0.0/8", "192.0.2.5/32"},
		ControllerIPs:         []string{"198.51.100.2"},
		ServiceScopes:         []safety.ServiceScope{{ServiceGroup: "lab-ssh", Service: "ssh", Transport: protocol.TransportTCP, Ports: []uint16{2222}}},
		MaxDecisionTTLSeconds: 120, MaxDecisions: 64,
	}
	raw, _ := json.Marshal(policy)
	if err := os.WriteFile(safetyFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := RuntimeConfig{
		NodeID: "lab-node-a", ServiceGroup: "lab-ssh", Mode: "observe", FirewallBackend: "simulated",
		ControllerURL: "https://127.0.0.1:9443", TLSCAFile: filepath.Join(dir, "ca.pem"),
		TokenFile: filepath.Join(dir, "token"), TrustedKeysFile: keys, SafetyPolicyFile: safetyFile,
		StateDir: stateDir, PollIntervalSeconds: 5, ReconcileIntervalSeconds: 1, MaxOfflineAgeSeconds: 90,
	}
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return configPath, FileStore{Dir: stateDir}, *now, priv
}
func TestReadOnlyOperatorSignedAcceptedAndSimulation(t *testing.T) {
	config, store, now, priv := operatorFixture(t)
	env := snapshot(t, priv, now, 1, "203.0.113.42/32")
	if err := store.Save(DurableState{Version: 1, Revision: 1, Signed: &env, AcceptedAt: now}); err != nil {
		t.Fatal(err)
	}
	view, err := InspectRuntime(context.Background(), config, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != 1 || view.SignerKeyID != "lab-key" || view.Acceptance != "current" ||
		view.Enforcement != "simulated_only" || view.KernelVerified || len(view.SignedDesired) != 1 || len(view.AcceptedEffective) != 1 || len(view.BackendObserved) != 0 {
		t.Fatalf("false live enforcement or lost signed state: %+v", view)
	}
	filtered, err := InspectRuntime(context.Background(), config, "203.0.113.99", now)
	if err != nil || len(filtered.SignedDesired) != 0 || len(filtered.AcceptedEffective) != 0 {
		t.Fatalf("wrong address filter: %+v %v", filtered, err)
	}
	filtered, err = InspectRuntime(context.Background(), config, "203.0.113.42", now)
	if err != nil || len(filtered.SignedDesired) != 1 {
		t.Fatalf("address filter lost decision: %+v %v", filtered, err)
	}
	future := now.Add(2 * time.Minute)
	expired, err := InspectRuntime(context.Background(), config, "", future)
	if err != nil {
		t.Fatal(err)
	}
	if expired.Acceptance != "expired" || len(expired.AcceptedEffective) != 0 || len(expired.SignedDesired) != 1 {
		t.Fatalf("expired snapshot treated as accepted: %+v", expired)
	}
	env.SignatureBase64 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 64)))
	if err := store.Save(DurableState{Version: 1, Revision: 1, Signed: &env, AcceptedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRuntime(context.Background(), config, "", now); err == nil {
		t.Fatal("tampered persisted policy trusted")
	}
}
func TestReadOnlyOperatorRejectsInvalidInspectAddresses(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "224.0.0.1", "2001:db8::1", "1.2.3.4/32", "001.2.3.4", "not-ip"} {
		if _, err := InspectSource(ip); err == nil {
			t.Fatalf("invalid IP accepted: %q", ip)
		}
	}
	if got, err := InspectSource("203.0.113.42"); err != nil || got != "203.0.113.42/32" {
		t.Fatalf("canonical IP: %q %v", got, err)
	}
}
