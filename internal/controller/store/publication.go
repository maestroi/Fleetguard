//go:build linux && cgo

package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// PublishApprovedDecision replaces the reporting nodes' cached snapshots in
// one transaction. Both the decision and its signed snapshot expire together.
func (s *DB) PublishApprovedDecision(group string, nodes []string, decision protocol.Decision, keyID string, key ed25519.PrivateKey, now time.Time) error {
	source, err := netip.ParsePrefix(decision.Source)
	if err != nil || !source.Addr().IsPrivate() || len(nodes) < 2 || len(decision.DestinationPorts) != 1 ||
		decision.ExpiresAt.Sub(now) > 2*time.Minute || len(key) != ed25519.PrivateKeySize {
		return errors.New("approval requires two reporting nodes and one private lab source and port for at most two minutes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transaction(func() error {
		seen := make(map[string]bool, len(nodes))
		for _, node := range nodes {
			if node == "" || seen[node] {
				return errors.New("approval requires distinct named reporting nodes")
			}
			seen[node] = true
			row, found, err := s.row("SELECT revision,expires_at,envelope FROM snapshots WHERE node_id=? AND group_id=?", node, group)
			if err != nil {
				return err
			}
			var revision uint64
			if found {
				revision, err = strconv.ParseUint(row[0], 10, 64)
				if err != nil {
					return err
				}
				expires, err := time.Parse(time.RFC3339Nano, row[1])
				if err != nil {
					return err
				}
				if now.Before(expires) {
					var wire protocol.SignedSnapshot
					if err := json.Unmarshal([]byte(row[2]), &wire); err != nil {
						return err
					}
					trusted := map[string]ed25519.PublicKey{keyID: key.Public().(ed25519.PublicKey)}
					current, err := protocol.VerifySignedSnapshot(wire, trusted, protocol.Audience{NodeID: node, ServiceGroup: group}, 0, now)
					if err != nil {
						return err
					}
					if len(current.Decisions) > 0 {
						return fmt.Errorf("node %s already has an active approval", node)
					}
				}
			}
			if _, err := s.writeSnapshot(node, group, keyID, key, revision, now, decision.ExpiresAt, []protocol.Decision{decision}); err != nil {
				return err
			}
		}
		_, err := s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), "decision_approved", "", group+" decision="+decision.ID)
		return err
	})
}

// writeSnapshot runs inside the caller's transaction.
func (s *DB) writeSnapshot(node, group, keyID string, key ed25519.PrivateKey, previous uint64, now, expires time.Time, decisions []protocol.Decision) (protocol.SignedSnapshot, error) {
	if previous == ^uint64(0) {
		return protocol.SignedSnapshot{}, errors.New("snapshot revision overflow")
	}
	snap := protocol.Snapshot{
		Schema: protocol.SchemaVersion, Revision: previous + 1,
		IssuedAt: now.UTC(), ExpiresAt: expires.UTC(),
		Audience:  protocol.Audience{ServiceGroup: group, NodeID: node},
		Decisions: decisions, KeyID: keyID,
	}
	envelope, err := protocol.SignSnapshot(snap, key)
	if err != nil {
		return envelope, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return envelope, err
	}
	revision := strconv.FormatUint(snap.Revision, 10)
	_, err = s.exec("INSERT INTO snapshots(node_id,group_id,revision,expires_at,envelope) VALUES(?,?,?,?,?) ON CONFLICT(node_id,group_id) DO UPDATE SET revision=excluded.revision,expires_at=excluded.expires_at,envelope=excluded.envelope", node, group, revision, instant(snap.ExpiresAt), string(raw))
	if err != nil {
		return envelope, err
	}
	_, err = s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), "policy_published", node, group+" revision="+revision)
	return envelope, err
}
