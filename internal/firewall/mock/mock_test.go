package mock

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func testDecision(now time.Time) protocol.Decision {
	return protocol.Decision{ID: "ban-1", Source: "203.0.113.42/32", Action: protocol.ActionDrop,
		Service: "public-rpc", Transport: protocol.TransportTCP,
		DestinationPorts: []uint16{8899}, ExpiresAt: now.Add(time.Minute), ReasonCode: "manual_fixture"}
}

func TestScopedIdempotentExpiryAndClear(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	b, err := New(c.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cap, err := b.Capabilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !cap.Simulated || !cap.IPv4 || !cap.ScopedPorts || cap.IPv6 || cap.ForwardedTraffic || cap.KernelExpiry {
		t.Fatalf("mock must never claim real enforcement capabilities: %+v", cap)
	}
	d := testDecision(c.now())
	for i := 0; i < 3; i++ {
		s, err := b.Reconcile(ctx, []protocol.Decision{d})
		if err != nil {
			t.Fatal(err)
		}
		if !s.Simulated || len(s.Decisions) != 1 || s.Decisions[0].Service != "public-rpc" || s.Decisions[0].DestinationPorts[0] != 8899 {
			t.Fatalf("unsafe or missing mock state: %+v", s)
		}
	}
	// Both inputs and returned slices must be defensive copies.
	d.DestinationPorts[0] = 22
	state, _ := b.Inspect(ctx)
	state.Decisions[0].DestinationPorts[0] = 22
	state, _ = b.Inspect(ctx)
	if state.Decisions[0].DestinationPorts[0] != 8899 {
		t.Fatal("internal mock state alias leaked")
	}
	c.advance(time.Minute)
	state, err = b.Inspect(ctx)
	if err != nil || len(state.Decisions) != 0 {
		t.Fatalf("expired decision remained: %+v %v", state, err)
	}
	state, err = b.Reconcile(ctx, []protocol.Decision{testDecision(c.now().Add(-time.Minute))})
	if err != nil || len(state.Decisions) != 0 {
		t.Fatalf("expired decision resurrected: %+v %v", state, err)
	}
	if err := b.RemoveOwned(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveOwned(ctx); err != nil {
		t.Fatal("RemoveOwned must be idempotent: ", err)
	}
}

func TestValidationAndAtomicity(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	b, _ := New(func() time.Time { return now })
	ctx := context.Background()
	d := testDecision(now)
	if _, err := b.Reconcile(ctx, []protocol.Decision{d}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		alter func(*protocol.Decision)
	}{
		{"broad_prefix", func(d *protocol.Decision) { d.Source = "203.0.113.0/24" }},
		{"any_source", func(d *protocol.Decision) { d.Source = "0.0.0.0/0" }},
		{"wrong_action", func(d *protocol.Decision) { d.Action = "execute" }},
		{"wrong_transport", func(d *protocol.Decision) { d.Transport = "any" }},
		{"empty_ports", func(d *protocol.Decision) { d.DestinationPorts = nil }},
		{"duplicate_ports", func(d *protocol.Decision) { d.DestinationPorts = []uint16{80, 80} }},
		{"excessive_ttl", func(d *protocol.Decision) { d.ExpiresAt = now.Add(protocol.MaxSnapshotTTL + time.Second) }},
		{"invalid_reason", func(d *protocol.Decision) { d.ReasonCode = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := testDecision(now)
			tc.alter(&bad)
			if _, err := b.Reconcile(ctx, []protocol.Decision{bad}); err == nil {
				t.Fatal("invalid decision accepted")
			}
			state, _ := b.Inspect(ctx)
			if len(state.Decisions) != 1 || state.Decisions[0].ID != "ban-1" {
				t.Fatal("invalid reconcile modified previous desired state")
			}
		})
	}
	if _, err := b.Reconcile(ctx, []protocol.Decision{d, d}); err == nil {
		t.Fatal("duplicate decision ID accepted")
	}
	large := make([]protocol.Decision, protocol.MaxDecisions+1)
	if _, err := b.Reconcile(ctx, large); err == nil {
		t.Fatal("overlarge desired set accepted")
	}
	for i := 0; i < protocol.MaxDecisions; i++ {
		e := testDecision(now)
		e.ID = fmt.Sprintf("ban-%03d", i)
		large[i] = e
	}
	state, err := b.Reconcile(ctx, large[:protocol.MaxDecisions])
	if err != nil || len(state.Decisions) != protocol.MaxDecisions {
		t.Fatalf("at-limit desired set: %v %+v", err, state)
	}
	if _, err := b.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	state, _ = b.Inspect(ctx)
	if len(state.Decisions) != 0 {
		t.Fatal("empty desired state did not revoke entries")
	}
}

func TestCancellationAndConcurrency(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrNoClock) {
		t.Fatal("nil clock must fail")
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	b, _ := New(func() time.Time { return now })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Capabilities(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := b.Inspect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := b.Reconcile(ctx, []protocol.Decision{testDecision(now)}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := b.RemoveOwned(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if i%2 == 0 {
					_, _ = b.Reconcile(context.Background(), []protocol.Decision{testDecision(now)})
				} else {
					_, _ = b.Inspect(context.Background())
				}
			}
		}(i)
	}
	wg.Wait()
}
