package safety

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func fixture() (Policy, protocol.Snapshot, Runtime, time.Time) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	p := Policy{Mode: "enforce", ProtectedCIDRs: []string{"10.0.0.0/8", "2001:db8::/32", "100.100.100.1/32"}, ControllerIPs: []string{"198.51.100.2"}, ManagementInterfaces: []string{"tailscale0"}, ServiceScopes: []ServiceScope{{ServiceGroup: "public-rpc", Service: "solana-rpc", Transport: protocol.TransportTCP, Ports: []uint16{443, 8899}}}, MaxDecisionTTLSeconds: 120, MaxDecisions: 2}
	s := protocol.Snapshot{Schema: protocol.SchemaVersion, Revision: 1, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), Audience: protocol.Audience{NodeID: "node-a", ServiceGroup: "public-rpc"}, KeyID: "lab-key", Decisions: []protocol.Decision{{ID: "ban-1", Source: "203.0.113.42/32", Action: protocol.ActionDrop, Service: "solana-rpc", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, ExpiresAt: now.Add(time.Minute), ReasonCode: "verified_multi_node_abuse"}}}
	r := Runtime{BackendName: "firewalld", Verified: true, Capabilities: firewall.Capabilities{IPv4: true, ScopedPorts: true}, InterfacePrefixes: func(name string) ([]netip.Prefix, error) {
		if name != "tailscale0" {
			return nil, errors.New("unknown")
		}
		return []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, nil
	}}
	return p, s, r, now
}
func TestSignedLocalProtectionAndScope(t *testing.T) {
	p, s, r, now := fixture()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"lab-key": pub}
	expected := protocol.Audience{NodeID: "node-a", ServiceGroup: "public-rpc"}
	check := func(s protocol.Snapshot, want string) {
		t.Helper()
		signed, err := protocol.SignSnapshot(s, priv)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyAndAuthorize(signed, keys, expected, 0, now, p, r)
		if want == "" {
			if err != nil {
				t.Fatalf("valid policy: %v", err)
			}
			return
		}
		var rejected *Rejection
		if !errors.As(err, &rejected) || rejected.Code != want {
			t.Fatalf("want %s, got %v", want, err)
		}
	}
	check(s, "")
	for _, ip := range []string{"10.3.4.5/32", "100.100.100.1/32", "100.80.4.7/32", "198.51.100.2/32"} {
		modified := s
		modified.Decisions = append([]protocol.Decision(nil), s.Decisions...)
		modified.Decisions[0].Source = ip
		check(modified, "protected_source")
	}
	for _, mutate := range []func(*protocol.Snapshot){
		func(s *protocol.Snapshot) { s.Decisions[0].DestinationPorts = []uint16{22} },
		func(s *protocol.Snapshot) { s.Decisions[0].Service = "ssh" },
		func(s *protocol.Snapshot) { s.Decisions[0].Transport = protocol.TransportUDP },
	} {
		modified := s
		modified.Decisions = append([]protocol.Decision(nil), s.Decisions...)
		mutate(&modified)
		check(modified, "scope_denied")
	}
	modified := s
	modified.Decisions = append([]protocol.Decision(nil), s.Decisions...)
	modified.Decisions[0].ExpiresAt = now.Add(121 * time.Second)
	// The enclosing signed snapshot also limits expiry; check the independent local cap.
	modified.ExpiresAt = now.Add(3 * time.Minute)
	check(modified, "ttl_exceeded")
	modified = s
	modified.Decisions = append([]protocol.Decision(nil), s.Decisions...)
	modified.Decisions = append(modified.Decisions, protocol.Decision{ID: "ban-2", Source: "203.0.113.43/32", Action: protocol.ActionDrop, Service: "solana-rpc", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, ExpiresAt: now.Add(time.Minute), ReasonCode: "verified_multi_node_abuse"}, protocol.Decision{ID: "ban-3", Source: "203.0.113.44/32", Action: protocol.ActionDrop, Service: "solana-rpc", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, ExpiresAt: now.Add(time.Minute), ReasonCode: "verified_multi_node_abuse"})
	check(modified, "too_many_decisions")
}
func TestUnsafeBackendAndInterfaceFailClosed(t *testing.T) {
	p, s, r, now := fixture()
	cases := []struct {
		name, code string
		change     func(*Policy, *Runtime)
	}{
		{"observe", "observe_only", func(p *Policy, r *Runtime) { p.Mode = "observe" }},
		{"disabled", "emergency_disabled", func(p *Policy, r *Runtime) { r.Disabled = true }},
		{"simulated", "unverified_backend", func(p *Policy, r *Runtime) { r.Capabilities.Simulated = true }},
		{"unknown", "unverified_backend", func(p *Policy, r *Runtime) { r.BackendName = "nftables" }},
		{"unverified", "unverified_backend", func(p *Policy, r *Runtime) { r.Verified = false }},
		{"no-scoping", "unverified_backend", func(p *Policy, r *Runtime) { r.Capabilities.ScopedPorts = false }},
		{"missing tailscale", "management_interface_unverified", func(p *Policy, r *Runtime) {
			r.InterfacePrefixes = func(string) ([]netip.Prefix, error) { return nil, errors.New("missing") }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp, cr := p, r
			tc.change(&cp, &cr)
			err := cp.Authorize(s, s.Audience, now, cr)
			var reject *Rejection
			if !errors.As(err, &reject) || reject.Code != tc.code {
				t.Fatalf("want %s got %v", tc.code, err)
			}
		})
	}
}
func TestLocalConfigStrictAndBroadCIDRs(t *testing.T) {
	p, s, r, now := fixture()
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(encoded); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"mode":"enforce","unknown":1}`), append(encoded, []byte(" {}")...), []byte("{"), make([]byte, maxPolicyBytes+1)} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	for _, cidr := range []string{"0.0.0.0/0", "203.0.113.0/24"} {
		cp := p
		cp.ProtectedCIDRs = []string{cidr}
		if err := cp.Authorize(s, s.Audience, now, r); err == nil {
			t.Fatalf("protected range %s ignored", cidr)
		}
	}
	// Even a correctly signed broad drop never reaches the local gate:
	// the protocol itself rejects any prefix wider than a host /32.
	s.Decisions[0].Source = "0.0.0.0/0"
	if err := p.Authorize(s, s.Audience, now, r); err == nil {
		t.Fatal("accepted broad source")
	}
}
func TestSignatureAndReplayStillRequired(t *testing.T) {
	p, s, r, now := fixture()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	wire, err := protocol.SignSnapshot(s, priv)
	if err != nil {
		t.Fatal(err)
	}
	expected := s.Audience
	keys := map[string]ed25519.PublicKey{"lab-key": pub}
	if _, err := VerifyAndAuthorize(wire, keys, expected, s.Revision, now, p, r); protocol.Reason(err) != protocol.ReasonReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	wire.SignatureBase64 = "corrupted"
	if _, err := VerifyAndAuthorize(wire, keys, expected, 0, now, p, r); err == nil {
		t.Fatal("bad signature accepted")
	}
}
