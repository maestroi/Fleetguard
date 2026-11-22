//go:build linux && cgo

package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type AckView struct {
	Revision   uint64                 `json:"revision"`
	State      protocol.DecisionState `json:"state"`
	Reason     protocol.ReasonCode    `json:"reason,omitempty"`
	ReceivedAt string                 `json:"received_at"`
}

// NodeAudit is scoped to one authenticated node and service group. Acks are
// agent *claims*, never evidence of kernel firewall application.
type NodeAudit struct {
	NodeID           string              `json:"node_id"`
	ServiceGroup     string              `json:"service_group"`
	EvidenceCount    int                 `json:"evidence_count"`
	Evidence         []protocol.Evidence `json:"evidence"`
	Revision         uint64              `json:"revision"`
	SignedSnapshot   *protocol.Snapshot  `json:"signed_snapshot,omitempty"`
	Acknowledgements []AckView           `json:"acknowledgements"`
	EnforcementProof string              `json:"enforcement_proof"`
}

// ReadNodeAudit exposes bounded, sanitized structured metadata only. It does
// not read arbitrary nodes, raw packet captures, tokens or private key paths.
func (s *DB) ReadNodeAudit(node, group string, limit int) (NodeAudit, error) {
	if node == "" || group == "" || limit < 1 || limit > 32 {
		return NodeAudit{}, errors.New("invalid node/group/audit limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := NodeAudit{NodeID: node, ServiceGroup: group, Evidence: []protocol.Evidence{}, Acknowledgements: []AckView{}, EnforcementProof: "unverified_agent_ack"}
	row, _, err := s.row("SELECT COUNT(*) FROM evidence WHERE node_id=? AND group_id=?", node, group)
	if err != nil {
		return NodeAudit{}, err
	}
	if len(row) > 0 {
		out.EvidenceCount, err = strconv.Atoi(row[0])
		if err != nil {
			return NodeAudit{}, err
		}
	}
	// Access through bounded individually indexed rows; do not require a
	// second CGo SQLite cursor or unbounded JSON result.
	for i := 0; i < limit; i++ {
		record, found, err := s.row("SELECT payload FROM evidence WHERE node_id=? AND group_id=? ORDER BY received_at DESC,event_id LIMIT 1 OFFSET ?", node, group, strconv.Itoa(i))
		if err != nil {
			return NodeAudit{}, err
		}
		if !found {
			break
		}
		var evidence protocol.Evidence
		if err := json.Unmarshal([]byte(record[0]), &evidence); err != nil {
			return NodeAudit{}, fmt.Errorf("invalid stored evidence: %w", err)
		}
		if evidence.NodeID != node {
			return NodeAudit{}, errors.New("stored evidence identity mismatch")
		}
		out.Evidence = append(out.Evidence, evidence)
	}
	row, found, err := s.row("SELECT revision,envelope FROM snapshots WHERE node_id=? AND group_id=?", node, group)
	if err != nil {
		return NodeAudit{}, err
	}
	if found {
		out.Revision, err = strconv.ParseUint(row[0], 10, 64)
		if err != nil {
			return NodeAudit{}, err
		}
		var signed protocol.SignedSnapshot
		if err := json.Unmarshal([]byte(row[1]), &signed); err != nil {
			return NodeAudit{}, err
		}
		payload, err := base64.RawStdEncoding.Strict().DecodeString(signed.PayloadBase64)
		if err != nil || len(payload) > protocol.MaxSnapshotBytes {
			return NodeAudit{}, errors.New("invalid stored snapshot encoding")
		}
		snap, err := protocol.ParseSnapshot(payload)
		if err != nil {
			return NodeAudit{}, err
		}
		if snap.Revision != out.Revision || snap.Audience.ServiceGroup != group || snap.Audience.NodeID != node {
			return NodeAudit{}, errors.New("stored snapshot scope/revision mismatch")
		}
		out.SignedSnapshot = &snap
	}
	for i := 0; i < 16; i++ {
		ack, found, err := s.row("SELECT revision,state,reason,received_at FROM acks WHERE node_id=? AND group_id=? ORDER BY received_at DESC,revision DESC LIMIT 1 OFFSET ?", node, group, strconv.Itoa(i))
		if err != nil {
			return NodeAudit{}, err
		}
		if !found {
			break
		}
		revision, err := strconv.ParseUint(ack[0], 10, 64)
		if err != nil {
			return NodeAudit{}, err
		}
		out.Acknowledgements = append(out.Acknowledgements, AckView{Revision: revision, State: protocol.DecisionState(ack[1]), Reason: protocol.ReasonCode(ack[2]), ReceivedAt: ack[3]})
	}
	return out, nil
}

type RetentionPurge struct {
	RetentionHours  int       `json:"retention_hours"`
	Before          time.Time `json:"before"`
	EvidenceRemoved int       `json:"evidence_removed"`
	AuditRemoved    int       `json:"audit_removed"`
}

// SetEvidenceRetention restricts source-IP evidence and audit text lifetime.
// Signed snapshots are revision watermarks and cannot be discarded here:
// deleting them can silently reset anti-replay state.
func (s *DB) SetEvidenceRetention(hours int) error {
	if hours < 1 || hours > 24 {
		return errors.New("retention must be between 1 and 24 hours")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retention = time.Duration(hours) * time.Hour
	return nil
}

// PurgeSensitive is an explicit, local-only operator action. Use ingestion's
// implicit pruning too so an active server never indefinitely retains data.
// Audit text may include operator-source IPs, hence it shares retention.
func (s *DB) PurgeSensitive(now time.Time) (RetentionPurge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var report RetentionPurge
	err := s.transaction(func() error {
		cutoff := now.UTC().Add(-s.retention)
		report.RetentionHours = int(s.retention / time.Hour)
		report.Before = cutoff
		var err error
		report.EvidenceRemoved, err = s.exec("DELETE FROM evidence WHERE received_at < ?", instant(cutoff))
		if err != nil {
			return err
		}
		report.AuditRemoved, err = s.exec("DELETE FROM audit WHERE received_at < ?", instant(cutoff))
		return err
	})
	return report, err
}
