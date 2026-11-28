package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// Fleet never-ban protection on the agent (#41).
//
// Trust: the list is verified against NeverBanKeys, a trust anchor disjoint
// from the policy signers, even though it arrived over authenticated HTTPS.
// Membership is add-only across restarts and signer rotations.
//
// Effect: protections only ever WITHHOLD bans. Every reconcile drops any
// central or local decision overlapping a protection, so an accepted update
// removes conflicting installed bans immediately and they cannot be restored.
//
// Freshness (NeverBanRequired): while the list is missing or expired, no new
// central or local ban is accepted; existing bans keep running only until
// list expiry + MaxOfflineAge, then all bans lapse. Protections are retained
// regardless of freshness; expiry and cleanup continue.

const (
	neverBanFilename      = "never-ban-v1.json"
	maxNeverBanStateBytes = protocol.MaxNeverBanWireBytes + 4096
)

// ProtectionState is the durable, root-owned record of the accepted list.
type ProtectionState struct {
	Version    int                          `json:"version"`
	Revision   uint64                       `json:"revision"`
	Signed     *protocol.SignedNeverBanList `json:"signed,omitempty"`
	AcceptedAt time.Time                    `json:"accepted_at,omitempty"`
}

type ProtectionStore interface {
	LoadProtection() (ProtectionState, error)
	SaveProtection(ProtectionState) error
}

func validProtectionState(st ProtectionState) bool {
	return st.Version == 1 && (st.Revision == 0) == (st.Signed == nil) && (st.Revision == 0 || !st.AcceptedAt.IsZero())
}

func (s FileStore) LoadProtection() (ProtectionState, error) {
	data, err := s.readPrivate(neverBanFilename, maxNeverBanStateBytes)
	if err != nil || data == nil {
		return ProtectionState{Version: 1}, err
	}
	var st ProtectionState
	if err := decodeStrict(data, &st); err != nil {
		return ProtectionState{}, err
	}
	if !validProtectionState(st) {
		return ProtectionState{}, errors.New("invalid persisted never-ban state")
	}
	return st, nil
}

func (s FileStore) SaveProtection(st ProtectionState) error {
	if !validProtectionState(st) {
		return errors.New("invalid never-ban state for persistence")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(data) > maxNeverBanStateBytes {
		return errors.New("never-ban state too large")
	}
	return s.writePrivate(neverBanFilename, data)
}

// validateNeverBanOptions enforces signer separation: no key ID or key
// material may be shared between policy and protection trust anchors.
func validateNeverBanOptions(o EngineOptions) error {
	if len(o.NeverBanKeys) == 0 {
		if o.NeverBanRequired {
			return errors.New("agent: never_ban_required needs never-ban trusted keys")
		}
		return nil
	}
	if o.ProtectionStore == nil {
		return errors.New("agent: never-ban trust requires a protection store")
	}
	for id, key := range o.NeverBanKeys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid never-ban key %q", id)
		}
		if _, clash := o.Keys[id]; clash {
			return errors.New("agent: never-ban signer must differ from policy signers")
		}
		for _, policyKey := range o.Keys {
			if key.Equal(policyKey) {
				return errors.New("agent: never-ban key material reused as policy key")
			}
		}
	}
	return nil
}

// loadProtection restores the accepted list. If it no longer verifies (e.g.
// the signer was rotated out), its structurally valid entries are RETAINED as
// protections: they can only withhold bans. It is never treated as fresh.
func (e *Engine) loadProtection(now time.Time) error {
	if e.options.ProtectionStore == nil {
		return nil
	}
	st, err := e.options.ProtectionStore.LoadProtection()
	if err != nil {
		return fmt.Errorf("load never-ban state: %w", err)
	}
	if st.Revision == 0 {
		return nil
	}
	if st.AcceptedAt.After(now.Add(protocol.MaxClockSkew)) {
		return errors.New("never-ban acceptance timestamp in the future; refusing clock rollback")
	}
	list, err := protocol.VerifyNeverBanList(*st.Signed, e.options.NeverBanKeys, st.Revision-1, st.AcceptedAt)
	if err != nil {
		retained, decodeErr := protocol.DecodeNeverBanUnverified(*st.Signed)
		if decodeErr != nil {
			return fmt.Errorf("persisted never-ban list unreadable: %w", decodeErr)
		}
		list = retained
		e.status.ProtectionUnverified = true
		e.setError(fmt.Errorf("retained unverified never-ban protections: %w", err))
	}
	if list.Revision != st.Revision {
		return errors.New("persisted never-ban watermark disagrees with payload")
	}
	e.setProtection(list, st.Signed, st.AcceptedAt)
	return nil
}

// ProtectionCategories fixes the order of Status.RejectedByCategory.
var ProtectionCategories = [4]protocol.ProtectionCategory{protocol.ProtectionInfrastructure, protocol.ProtectionPeers, protocol.ProtectionPartners, protocol.ProtectionEdge}

func (e *Engine) setProtection(list protocol.NeverBanList, signed *protocol.SignedNeverBanList, acceptedAt time.Time) {
	e.prot = list
	e.protSigned = signed
	e.protIndex = protocol.NeverBanIndex(list)
	e.protCategory = make(map[netip.Prefix]int, len(list.Entries))
	for _, entry := range list.Entries {
		p, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			continue
		}
		for i, c := range ProtectionCategories {
			if c == entry.Category {
				if prev, ok := e.protCategory[p]; !ok || i < prev {
					e.protCategory[p] = i // deterministic for multi-category CIDRs
				}
			}
		}
	}
	e.status.ProtectionRevision = list.Revision
	e.status.ProtectionEntries = e.protIndex.Len()
	e.status.ProtectionExpiresAt = list.ExpiresAt
	e.status.ProtectionAcceptedAt = acceptedAt
}

// AcceptNeverBan verifies, persists, then activates a signed protection list.
// Identical repeats are idempotent. A failure leaves prior protections intact.
func (e *Engine) AcceptNeverBan(ctx context.Context, envelope protocol.SignedNeverBanList) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.options.NeverBanKeys) == 0 {
		return errors.New("never-ban trust not configured")
	}
	// Idempotent only for a list verified under the CURRENT anchor; a
	// retained unverified list must re-verify (and fail) like any update.
	if e.protSigned != nil && *e.protSigned == envelope && !e.status.ProtectionUnverified {
		return nil
	}
	now := e.options.Now()
	next, err := protocol.VerifyNeverBanUpdate(envelope, e.options.NeverBanKeys, e.prot, now)
	if err != nil {
		e.status.InvalidProtection++
		e.setError(fmt.Errorf("never-ban update rejected: %w", err))
		return err
	}
	if err := e.options.ProtectionStore.SaveProtection(ProtectionState{Version: 1, Revision: next.Revision, Signed: &envelope, AcceptedAt: now}); err != nil {
		e.setError(err)
		return err
	}
	e.setProtection(next, &envelope, now)
	e.status.ProtectionUnverified = false
	e.status.ProtectionUpdates++
	// Remove conflicting installed bans now rather than at the next tick.
	if err := e.reconcile(ctx); err != nil {
		e.status.ReconcileErrors++
		return err
	}
	return nil
}

// protectionFresh requires a list verified under the current anchor; retained
// unverified entries still withhold bans but never authorize new ones.
func (e *Engine) protectionFresh(now time.Time) bool {
	return e.prot.Revision > 0 && !e.status.ProtectionUnverified && e.prot.ExpiresAt.After(now) && !e.prot.IssuedAt.After(now.Add(protocol.MaxClockSkew))
}

// protectionAllowsExisting reports whether already accepted bans may keep
// running. With a required list they survive staleness only for one
// MaxOfflineAge grace period after list expiry, and never without a list.
func (e *Engine) protectionAllowsExisting(now time.Time) bool {
	if !e.options.NeverBanRequired || e.protectionFresh(now) {
		return true
	}
	return e.prot.Revision > 0 && now.Before(e.prot.ExpiresAt.Add(e.options.MaxOfflineAge))
}

// protectionAllowsNew reports whether a NEW ban may be accepted.
func (e *Engine) protectionAllowsNew(now time.Time) bool {
	return !e.options.NeverBanRequired || e.protectionFresh(now)
}

// countProtectedRejection records a refused ban by the matching category.
func (e *Engine) countProtectedRejection(d protocol.Decision) {
	e.status.RejectedProtectedSource++
	if source, err := netip.ParsePrefix(d.Source); err == nil {
		if match, ok := e.protIndex.Match(source); ok {
			e.status.RejectedByCategory[e.protCategory[match]]++
		}
	}
}

func (e *Engine) protected(d protocol.Decision) bool {
	source, err := netip.ParsePrefix(d.Source)
	if err != nil {
		return true // fail closed
	}
	return e.protIndex.Overlaps(source)
}

// onlyExisting reports whether every decision is already live in the current
// accepted snapshot, i.e. the update can only remove bans.
func (e *Engine) onlyExisting(decisions []protocol.Decision, now time.Time) bool {
	if len(decisions) == 0 {
		return true
	}
	if e.snapshot == nil {
		return false
	}
	live := make(map[string]protocol.Decision, len(e.snapshot.Decisions))
	for _, d := range prune(e.snapshot.Decisions, now) {
		live[d.ID] = d
	}
	for _, d := range decisions {
		current, ok := live[d.ID]
		if !ok || !reflect.DeepEqual(current, d) {
			return false
		}
	}
	return true
}

// withholdProtected removes protected decisions, counting removals of bans
// the backend last reported as installed.
func (e *Engine) withholdProtected(in []protocol.Decision) (kept []protocol.Decision, withheld int) {
	kept = in[:0]
	for _, d := range in {
		if e.protected(d) {
			withheld++
			if e.applied[d.ID] {
				e.status.ProtectionRemovals++
			}
			continue
		}
		kept = append(kept, d)
	}
	return kept, withheld
}
