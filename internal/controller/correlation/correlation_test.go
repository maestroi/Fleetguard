package correlation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var fixed = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func lab() (Config, auth.Registry) {
	cfg := Config{Schema: 1, Mode: "observe", Group: "public-rpc", WindowSeconds: 120, DecisionTTLSeconds: 60, MinNodes: 2, MinDomains: 2, MaxEvidence: 512, MaxCandidates: 32, NodeDomains: map[string]string{"a": "rack-a", "b": "rack-b", "c": "rack-a"}, Scopes: []Scope{{Service: "public-rpc", Observation: "application_abuse", Transport: protocol.TransportTCP, Port: 8899}}, ProtectedSources: []string{"192.0.2.0/24"}, SharedNATSources: []string{"198.51.100.0/24"}}
	registry := auth.Registry{Groups: map[string]auth.Group{"public-rpc": {Services: []string{"public-rpc"}}, "other": {Services: []string{"other"}}}, Nodes: []auth.Node{{NodeID: "a", Groups: []string{"public-rpc"}}, {NodeID: "b", Groups: []string{"public-rpc"}}, {NodeID: "c", Groups: []string{"public-rpc"}}, {NodeID: "revoked", Groups: []string{"public-rpc"}, Revoked: true}}}
	return cfg, registry
}
func event(node, ip, proof, id string) protocol.Evidence {
	return protocol.Evidence{Schema: 1, EventID: id, NodeID: node, DedupKey: id, ObservedAt: fixed.Add(-10 * time.Second), WindowSeconds: 30, SourceIP: ip, Service: "public-rpc", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, Observation: "application_abuse", Attempts: 10, ProofLevel: protocol.ProofLevel(proof)}
}
func app(node, id string) protocol.Evidence {
	return event(node, "203.0.113.42", string(protocol.ProofApplicationVerified), id)
}
func TestTwoIndependentDomainsProposeObserveOnly(t *testing.T) {
	cfg, registry := lab()
	r, err := Evaluate(cfg, registry, []protocol.Evidence{app("a", "a1"), app("b", "b1")}, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != "observe_only" || r.RealFirewallWrites != 0 || r.PublishedPolicies != 0 || len(r.Candidates) != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
	c := r.Candidates[0]
	if c.Status != "candidate" || c.ReasonCode != "verified_multi_node_abuse" || c.Decision == nil || c.Decision.Source != "203.0.113.42/32" || c.Decision.Service != "public-rpc" || !reflect.DeepEqual(c.Decision.DestinationPorts, []uint16{8899}) || c.Decision.ExpiresAt != fixed.Add(60*time.Second) || !slices.Equal(c.Nodes, []string{"a", "b"}) {
		t.Fatalf("unexpected candidate: %+v", c)
	}
}
func TestNoSingleNodeOrOneDomainPromotion(t *testing.T) {
	cfg, registry := lab()
	in := []protocol.Evidence{}
	for i := 0; i < 50; i++ {
		e := app("a", "first")
		e.EventID = "event" + string(rune(65+i))
		e.DedupKey = e.EventID
		e.Attempts = 1000000
		in = append(in, e)
	}
	r, err := Evaluate(cfg, registry, in, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("noisy one node promoted: %+v %v", r, err)
	}
	r, err = Evaluate(cfg, registry, []protocol.Evidence{app("a", "a1"), app("c", "c1")}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("one independence domain promoted: %+v %v", r, err)
	}
}
func TestWeakSpoofableProofNeverPromotes(t *testing.T) {
	for _, p := range []protocol.ProofLevel{protocol.ProofUnverifiedLog, protocol.ProofEstablishedConnection} {
		cfg, registry := lab()
		a, b := app("a", "a1"), app("b", "b1")
		a.ProofLevel = p
		b.ProofLevel = p
		r, err := Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
		if err != nil || len(r.Candidates) > 0 || r.WeakEvidence != 2 {
			t.Fatalf("weak proof %s promoted: %+v %v", p, r, err)
		}
	}
	cfg, registry := lab()
	a, b := app("a", "a1"), app("b", "b1")
	a.Transport = protocol.TransportUDP
	b.Transport = protocol.TransportUDP
	r, err := Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("UDP promoted outside allowlisted scope: %+v %v", r, err)
	}
}
func TestSharedNATAndProtected(t *testing.T) {
	cfg, registry := lab()
	a, b := app("a", "a1"), app("b", "b1")
	a.SourceIP = "198.51.100.42"
	b.SourceIP = a.SourceIP
	r, err := Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 1 || r.Candidates[0].Status != "manual_review" || r.Candidates[0].Decision != nil || r.Candidates[0].ReasonCode != "shared_nat_review" {
		t.Fatalf("NAT not held: %+v %v", r, err)
	}
	a.SourceIP = "192.0.2.44"
	b.SourceIP = a.SourceIP
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 || r.SourcesSuppressed != 1 {
		t.Fatalf("protected source not suppressed: %+v %v", r, err)
	}
}
func TestOrderDuplicatesClockSkewAndExpiry(t *testing.T) {
	cfg, registry := lab()
	a, b := app("a", "a1"), app("b", "b1")
	a.Attempts = 250
	b.Attempts = 330
	data := []protocol.Evidence{b, a, a, b}
	r1, err := Evaluate(cfg, registry, data, fixed)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(data)
	r2, err := Evaluate(cfg, registry, data, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r1, r2) || len(r1.Candidates) != 1 || r1.Candidates[0].AttemptsCapped != 200 {
		t.Fatalf("order or saturation mismatch: %+v %+v", r1, r2)
	}
	b.ObservedAt = fixed.Add(10 * time.Second)
	r, err := Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("future observation counted: %+v %v", r, err)
	}
	b.ObservedAt = fixed.Add(-time.Duration(cfg.WindowSeconds+1) * time.Second)
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("expired observation counted: %+v %v", r, err)
	}
}
func TestIdentityScopeAndObservationIsolation(t *testing.T) {
	cfg, registry := lab()
	a, b := app("a", "a1"), app("b", "b1")
	b.Observation = "login_success"
	r, err := Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("unsanctioned observation counted: %+v %v", r, err)
	}
	b = app("unknown", "b1")
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("unknown identity counted: %+v %v", r, err)
	}
	cfg.NodeDomains["revoked"] = "rack-b"
	b = app("revoked", "b1")
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("revoked counted: %+v %v", r, err)
	}
	b = app("b", "b1")
	b.Service = "other"
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("cross-service evidence counted: %+v %v", r, err)
	}
	b = app("b", "b1")
	b.DestinationPorts = []uint16{22}
	r, err = Evaluate(cfg, registry, []protocol.Evidence{a, b}, fixed)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatalf("port not scoped: %+v %v", r, err)
	}
}
func TestCapacityAndExplicitPolicy(t *testing.T) {
	cfg, registry := lab()
	cfg.MaxEvidence = 1
	_, err := Evaluate(cfg, registry, []protocol.Evidence{app("a", "a1"), app("b", "b1")}, fixed)
	if err == nil {
		t.Fatal("over-capacity evidence must fail closed")
	}
	cfg, registry = lab()
	cfg.MaxCandidates = 1
	d := []protocol.Evidence{app("a", "a1"), app("b", "b1")}
	a, b := app("a", "a2"), app("b", "b2")
	a.SourceIP = "203.0.113.43"
	b.SourceIP = "203.0.113.43"
	d = append(d, a, b)
	_, err = Evaluate(cfg, registry, d, fixed)
	if err == nil {
		t.Fatal("over-capacity candidates must fail closed")
	}
	cfg, _ = lab()
	cfg.MinNodes = 1
	if err := Validate(cfg); err == nil {
		t.Fatal("single-node policy accepted")
	}
	cfg, _ = lab()
	cfg.Mode = "enforce"
	if err := Validate(cfg); err == nil {
		t.Fatal("enforcement policy accepted")
	}
	cfg, _ = lab()
	cfg.NodeDomains["b"] = "rack-a"
	if err := Validate(cfg); err == nil {
		t.Fatal("same-domain policy accepted")
	}
	cfg, _ = lab()
	cfg.Scopes = nil
	if err := Validate(cfg); err == nil {
		t.Fatal("empty scopes accepted")
	}
}
func TestLoadPrivatePolicy(t *testing.T) {
	cfg, _ := lab()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Group != cfg.Group {
		t.Fatalf("load: %+v %v", loaded, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("public config allowed")
	}
}

func TestFixtureNATAndSpoofableLogOnly(t *testing.T) {
	for _, tc := range []struct{ file, expected string }{
		{"shared_nat.json", "manual_review"},
		{"spoofable_only.json", ""},
	} {
		t.Run(tc.file, func(t *testing.T) {
			cfg, registry := lab()
			b, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			var events []protocol.Evidence
			if err = json.Unmarshal(b, &events); err != nil {
				t.Fatal(err)
			}
			for _, e := range events {
				if err := protocol.ValidateEvidence(e, e.NodeID, fixed); err != nil {
					t.Fatal(err)
				}
			}
			r, err := Evaluate(cfg, registry, events, fixed)
			if err != nil {
				t.Fatal(err)
			}
			if tc.expected == "" {
				if len(r.Candidates) != 0 || r.WeakEvidence != 2 {
					t.Fatalf("weak fixture improperly promoted: %+v", r)
				}
			} else if len(r.Candidates) != 1 || r.Candidates[0].Status != tc.expected || r.Candidates[0].Decision != nil {
				t.Fatalf("NAT fixture not held: %+v", r)
			}
		})
	}
}
