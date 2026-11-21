// Package mock is a rootless, in-memory firewall simulation. It does not
// interact with firewalld, nftables, iptables, the kernel or host networking.
package mock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var ErrNoClock = errors.New("mock firewall: injected clock is required")

// Backend contains exclusively mock-owned decisions. All calls are safe for
// concurrent use. Expiry is applied against the injected clock on reads and
// writes, so advancing virtual time is sufficient to simulate expiration.
type Backend struct {
	mu        sync.Mutex
	now       func() time.Time
	decisions map[string]protocol.Decision
}

var _ firewall.Backend = (*Backend)(nil)

func New(now func() time.Time) (*Backend, error) {
	if now == nil {
		return nil, ErrNoClock
	}
	return &Backend{now: now, decisions: make(map[string]protocol.Decision)}, nil
}

func (b *Backend) Capabilities(ctx context.Context) (firewall.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return firewall.Capabilities{}, err
	}
	return firewall.Capabilities{IPv4: true, ScopedPorts: true, Simulated: true}, nil
}

// Reconcile atomically replaces the mock-owned set. Expired decisions are
// dropped rather than resurrected. All remaining decisions are validated with
// protocol-v1 structural and lifetime limits, including exact /32 sources and
// explicit destination ports; failure leaves the current state unchanged.
// This is NOT signature validation or local safety authorization.
func (b *Backend) Reconcile(ctx context.Context, desired []protocol.Decision) (firewall.AppliedState, error) {
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	now := b.now()
	if len(desired) > protocol.MaxDecisions {
		return firewall.AppliedState{}, fmt.Errorf("mock firewall: at most %d decisions allowed", protocol.MaxDecisions)
	}
	active := make([]protocol.Decision, 0, len(desired))
	for _, d := range desired {
		if d.ExpiresAt.After(now) {
			active = append(active, clone(d))
		}
	}
	// Use the same strict decision checks as the signed snapshot format.
	// The synthetic snapshot is a validation container, not an authority.
	if err := protocol.ValidateSnapshot(protocol.Snapshot{
		Schema: protocol.SchemaVersion, Revision: 1,
		IssuedAt: now, ExpiresAt: now.Add(protocol.MaxSnapshotTTL),
		Audience:  protocol.Audience{ServiceGroup: "simulation"},
		Decisions: active, KeyID: "simulation",
	}); err != nil {
		return firewall.AppliedState{}, fmt.Errorf("mock firewall: invalid desired state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	next := make(map[string]protocol.Decision, len(active))
	for _, d := range active {
		next[d.ID] = d
	}
	b.decisions = next
	return b.snapshotLocked(now), nil
}

func (b *Backend) Inspect(ctx context.Context) (firewall.AppliedState, error) {
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	now := b.now()
	b.pruneLocked(now)
	return b.snapshotLocked(now), nil
}

// RemoveOwned cannot affect real firewall rules or any other backend's state.
func (b *Backend) RemoveOwned(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	b.decisions = make(map[string]protocol.Decision)
	return nil
}

func (b *Backend) pruneLocked(now time.Time) {
	for id, d := range b.decisions {
		if !d.ExpiresAt.After(now) {
			delete(b.decisions, id)
		}
	}
}
func (b *Backend) snapshotLocked(now time.Time) firewall.AppliedState {
	b.pruneLocked(now)
	ids := make([]string, 0, len(b.decisions))
	for id := range b.decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	state := firewall.AppliedState{ObservedAt: now, Decisions: make([]protocol.Decision, 0, len(ids)), Simulated: true}
	for _, id := range ids {
		state.Decisions = append(state.Decisions, clone(b.decisions[id]))
	}
	return state
}
func clone(d protocol.Decision) protocol.Decision {
	d.DestinationPorts = append([]uint16(nil), d.DestinationPorts...)
	return d
}
