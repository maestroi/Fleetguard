package firewalld

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type fake struct {
	status  Status
	sets    map[string]SetSettings
	entries map[string]map[string]bool
	rules   map[string]bool
	calls   []string
	failOn  string
}

func (f *fake) Status(ctx context.Context) (Status, error) { return f.status, ctx.Err() }
func (f *fake) IPSetSettings(ctx context.Context, name string) (SetSettings, error) {
	if err := ctx.Err(); err != nil {
		return SetSettings{}, err
	}
	s, ok := f.sets[name]
	if !ok {
		return SetSettings{}, errors.New("set not provisioned")
	}
	return s, nil
}
func (f *fake) Entries(ctx context.Context, name string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.entries[name]))
	for ip := range f.entries[name] {
		out = append(out, ip)
	}
	return out, nil
}
func (f *fake) RichRules(ctx context.Context, zone string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.rules))
	for rule := range f.rules {
		out = append(out, rule)
	}
	return out, nil
}
func (f *fake) mutate(ctx context.Context, kind, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.calls = append(f.calls, kind+" "+key)
	if kind == f.failOn {
		return errors.New("injected D-Bus failure")
	}
	return nil
}
func (f *fake) AddEntry(ctx context.Context, name, ip string) error {
	if err := f.mutate(ctx, "add-entry", name+"/"+ip); err != nil {
		return err
	}
	f.entries[name][ip] = true
	return nil
}
func (f *fake) RemoveEntry(ctx context.Context, name, ip string) error {
	if err := f.mutate(ctx, "remove-entry", name+"/"+ip); err != nil {
		return err
	}
	delete(f.entries[name], ip)
	return nil
}
func (f *fake) AddRichRule(ctx context.Context, zone, rule string) error {
	if err := f.mutate(ctx, "add-rule", zone+"/"+rule); err != nil {
		return err
	}
	f.rules[rule] = true
	return nil
}
func (f *fake) RemoveRichRule(ctx context.Context, zone, rule string) error {
	if err := f.mutate(ctx, "remove-rule", zone+"/"+rule); err != nil {
		return err
	}
	delete(f.rules, rule)
	return nil
}

func fixture(t testing.TB) (*Backend, *fake, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	p := safety.Policy{
		Mode: "enforce", ProtectedCIDRs: []string{"10.0.0.0/8", "100.64.0.0/10"},
		ControllerIPs: []string{"198.51.100.9"}, MaxDecisions: 256, MaxDecisionTTLSeconds: 120,
		ServiceScopes: []safety.ServiceScope{{ServiceGroup: "rpc", Service: "web", Transport: protocol.TransportTCP, Ports: []uint16{443, 8899}}},
	}
	o := Options{Zone: "public", Audience: protocol.Audience{NodeID: "lab-a", ServiceGroup: "rpc"}, Policy: p,
		HostINPUTVerified: true, Bindings: []Binding{{Service: "web", Transport: protocol.TransportTCP, Port: 443}, {Service: "web", Transport: protocol.TransportTCP, Port: 8899}},
		Now: func() time.Time { return now },
	}
	f := &fake{status: Status{State: "RUNNING", Version: "2.1.1", Backend: "nftables", IPv4: true, IPSet: true,
		IPSetTypes: []string{"hash:ip", "hash:net"}, ActiveZones: map[string]map[string][]string{"public": {"interfaces": {"eth0"}, "sources": {}}}},
		sets: map[string]SetSettings{}, entries: map[string]map[string]bool{}, rules: map[string]bool{"rule family=\"ipv4\" source address=\"198.51.100.111\" port port=\"444\" protocol=\"tcp\" accept": true}}
	for _, binding := range o.Bindings {
		name := SetName(o.Zone, o.Audience, binding)
		f.sets[name] = SetSettings{Type: "hash:ip", Description: SetDescription(o.Zone, o.Audience, binding), Options: map[string]string{"family": "inet"}}
		f.entries[name] = map[string]bool{}
	}
	b, err := New(f, o)
	if err != nil {
		t.Fatal(err)
	}
	return b, f, &now
}
func decision(i int, now time.Time, ports ...uint16) protocol.Decision {
	source := fmt.Sprintf("198.18.%d.%d/32", (i/254)%256, (i%254)+1)
	return protocol.Decision{ID: fmt.Sprintf("ban-%d", i), Source: source, Action: protocol.ActionDrop, Service: "web",
		Transport: protocol.TransportTCP, DestinationPorts: ports, ExpiresAt: now.Add(time.Minute), ReasonCode: "verified_multi_node_abuse"}
}
func TestReconcileScopedIdempotentAndOwned(t *testing.T) {
	b, f, now := fixture(t)
	foreign := f.rules["rule family=\"ipv4\" source address=\"198.51.100.111\" port port=\"444\" protocol=\"tcp\" accept"]
	if !foreign {
		t.Fatal("fixture should have a foreign rule")
	}
	choices := []protocol.Decision{decision(0, *now, 443, 8899), decision(1, *now, 8899)}
	ctx := context.Background()
	if _, err := b.Capabilities(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := b.Reconcile(ctx, choices)
	if err != nil {
		t.Fatal(err)
	}
	if state.Simulated || len(state.Decisions) != 2 {
		t.Fatalf("unexpected applied state: %+v", state)
	}
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		if !f.rules[RichRule(b.options.Zone, b.options.Audience, binding)] {
			t.Fatal("missing scoped rich rule")
		}
		if !f.entries[name]["198.18.0.1"] {
			t.Fatal("missing expected IP")
		}
		if binding.Port == 443 && f.entries[name]["198.18.0.2"] {
			t.Fatal("different-port ban leaked into 443/tcp")
		}
	}
	before := len(f.calls)
	if _, err := b.Reconcile(ctx, choices); err != nil {
		t.Fatal(err)
	}
	if got := len(f.calls); got != before {
		t.Fatalf("idempotent reconcile made %d writes", got-before)
	}
	observed, err := b.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed.Decisions, state.Decisions) {
		t.Fatalf("inspect mismatch: %+v", observed)
	}
	if err := b.RemoveOwned(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.rules["rule family=\"ipv4\" source address=\"198.51.100.111\" port port=\"444\" protocol=\"tcp\" accept"] {
		t.Fatal("foreign rule removed")
	}
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		if len(f.entries[name]) != 0 || f.rules[RichRule(b.options.Zone, b.options.Audience, binding)] {
			t.Fatal("owned objects remain after cleanup")
		}
	}
	if _, err := b.Inspect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveOwned(ctx); err != nil {
		t.Fatal("repeated cleanup should be idempotent: ", err)
	}
}
func TestRejectBeforeAnyMutation(t *testing.T) {
	cases := []struct {
		name      string
		modify    func(*Backend, *fake, *time.Time)
		decisions func(time.Time) []protocol.Decision
	}{
		{"observe mode", func(b *Backend, f *fake, n *time.Time) { b.options.Policy.Mode = "observe" }, nil},
		{"attestation missing", func(b *Backend, f *fake, n *time.Time) { b.options.HostINPUTVerified = false }, nil},
		{"iptables", func(b *Backend, f *fake, n *time.Time) { f.status.Backend = "iptables" }, nil},
		{"unknown version", func(b *Backend, f *fake, n *time.Time) { f.status.Version = "unknown" }, nil},
		{"extra zone", func(b *Backend, f *fake, n *time.Time) {
			f.status.ActiveZones["trusted"] = map[string][]string{"interfaces": {"tun0"}}
		}, nil},
		{"source zone", func(b *Backend, f *fake, n *time.Time) {
			f.status.ActiveZones["public"]["sources"] = []string{"192.0.2.0/24"}
		}, nil},
		{"missing ipset", func(b *Backend, f *fake, n *time.Time) {
			delete(f.sets, SetName(b.options.Zone, b.options.Audience, b.options.Bindings[0]))
		}, nil},
		{"foreign set description", func(b *Backend, f *fake, n *time.Time) {
			name := SetName(b.options.Zone, b.options.Audience, b.options.Bindings[0])
			x := f.sets[name]
			x.Description = "other program"
			f.sets[name] = x
		}, nil},
		{"timed set", func(b *Backend, f *fake, n *time.Time) {
			name := SetName(b.options.Zone, b.options.Audience, b.options.Bindings[0])
			x := f.sets[name]
			x.Options["timeout"] = "60"
			f.sets[name] = x
		}, nil},
		{"unsafe protected source", nil, func(now time.Time) []protocol.Decision {
			d := decision(0, now, 443)
			d.Source = "10.1.2.3/32"
			return []protocol.Decision{d}
		}},
		{"controller source", nil, func(now time.Time) []protocol.Decision {
			d := decision(0, now, 443)
			d.Source = "198.51.100.9/32"
			return []protocol.Decision{d}
		}},
		{"unauthorized port", nil, func(now time.Time) []protocol.Decision { return []protocol.Decision{decision(0, now, 22)} }},
		{"global /0", nil, func(now time.Time) []protocol.Decision {
			d := decision(0, now, 443)
			d.Source = "0.0.0.0/0"
			return []protocol.Decision{d}
		}},
		{"max count", nil, func(now time.Time) []protocol.Decision {
			out := make([]protocol.Decision, 257)
			for i := range out {
				out[i] = decision(i, now, 443)
			}
			return out
		}},
		{"expired", nil, func(now time.Time) []protocol.Decision {
			d := decision(0, now, 443)
			d.ExpiresAt = now.Add(-time.Second)
			return []protocol.Decision{d}
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			b, f, now := fixture(t)
			if tt.modify != nil {
				tt.modify(b, f, now)
			}
			desired := []protocol.Decision{decision(0, *now, 443)}
			if tt.decisions != nil {
				desired = tt.decisions(*now)
			}
			_, err := b.Reconcile(context.Background(), desired)
			if tt.name == "expired" {
				if err != nil {
					t.Fatalf("empty desired should be safe: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe enforcement accepted")
			}
			if len(f.calls) != 0 {
				t.Fatalf("unsafe state reached D-Bus mutation: %v", f.calls)
			}
		})
	}
}
func TestNoFalseAppliedStateOnPartialFailureOrRestart(t *testing.T) {
	b, f, now := fixture(t)
	ctx := context.Background()
	f.failOn = "add-entry"
	if _, err := b.Reconcile(ctx, []protocol.Decision{decision(0, *now, 443)}); err == nil {
		t.Fatal("partial apply reported success")
	}
	f.failOn = ""
	if _, err := b.Reconcile(ctx, []protocol.Decision{decision(0, *now, 443)}); err != nil {
		t.Fatal(err)
	}
	// A fresh process cannot claim a persisted rule's ID/expiry from D-Bus.
	restarted, err := New(f, b.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Inspect(ctx); !errors.Is(err, ErrDrift) {
		t.Fatalf("unexpected restart inspect: %v", err)
	}
	if _, err := restarted.Reconcile(ctx, nil); err != nil {
		t.Fatal("restart must clean unknown old ban: ", err)
	}
	if state, err := restarted.Inspect(ctx); err != nil || len(state.Decisions) != 0 {
		t.Fatalf("restart cleanup: %+v %v", state, err)
	}
}
func TestExpiryAndContext(t *testing.T) {
	b, _, now := fixture(t)
	ctx := context.Background()
	if _, err := b.Reconcile(ctx, []protocol.Decision{decision(0, *now, 443)}); err != nil {
		t.Fatal(err)
	}
	*now = (*now).Add(61 * time.Second)
	if _, err := b.Inspect(ctx); !errors.Is(err, ErrDrift) {
		t.Fatalf("expired entry must not claim applied state: %v", err)
	}
	if _, err := b.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Reconcile(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reconcile: %v", err)
	}
}
func TestNameDomainSeparation(t *testing.T) {
	if got := SetName("public", protocol.Audience{NodeID: "lab-a", ServiceGroup: "rpc"}, Binding{Service: "web", Transport: protocol.TransportTCP, Port: 8899}); got != "fg1_1249d4bd57f69425" {
		t.Fatalf("set-name contract changed: %s", got)
	}
	a := protocol.Audience{NodeID: "node-a", ServiceGroup: "rpc"}
	b := Binding{Service: "web", Transport: protocol.TransportTCP, Port: 443}
	n := SetName("public", a, b)
	if len(n) > 31 || n == SetName("trusted", a, b) {
		t.Fatal("bad owned set namespace")
	}
	b.Port = 444
	if n == SetName("public", a, b) {
		t.Fatal("ports share set")
	}
	b.Port = 443
	b.Transport = protocol.TransportUDP
	if n == SetName("public", a, b) {
		t.Fatal("protocols share set")
	}
	a.NodeID = "node-b"
	if n == SetName("public", a, Binding{Service: "web", Transport: protocol.TransportTCP, Port: 443}) {
		t.Fatal("distinct local node identities share a set")
	}
}

func BenchmarkReconcile(b *testing.B) {
	for _, n := range []int{1, 100, 10000} {
		b.Run(fmt.Sprintf("decisions_%d", n), func(b *testing.B) {
			fw, _, now := fixture(b)
			input := make([]protocol.Decision, n)
			for i := range input {
				input[i] = decision(i, *now, 443)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := fw.Reconcile(context.Background(), input)
				if n > protocol.MaxDecisions {
					if err == nil {
						b.Fatal("cap ignored")
					}
				} else if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
