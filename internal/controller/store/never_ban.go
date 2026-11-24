//go:build linux && cgo

package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var ErrNeverBanMissing = errors.New("no fleet never-ban revision exists")

// NeverBanRevision contains independently verified signed membership plus local
// operator metadata. The metadata is not included in the wire signature.
type NeverBanRevision struct {
	List     protocol.NeverBanList       `json:"list"`
	Envelope protocol.SignedNeverBanList `json:"envelope"`
	Actor    string                     `json:"actor"`
	Reason   string                     `json:"reason"`
}

// readNeverBanRevision requires the caller to hold the DB mutex. Historical
// lists are verified at their recorded issuance, not at the current time;
// expiry must not allow removal of previously accepted protections.
func (s *DB) readNeverBanRevision(revision uint64, keys map[string]ed25519.PublicKey) (NeverBanRevision, error) {
	var result NeverBanRevision
	var row []string
	var found bool
	var err error
	if revision == 0 {
		row, found, err = s.row("SELECT revision,issued_at,envelope,actor,reason FROM never_ban_revisions ORDER BY revision DESC LIMIT 1")
	} else {
		if revision > math.MaxInt64 {
			return result, errors.New("never-ban revision exceeds SQLite range")
		}
		row, found, err = s.row("SELECT revision,issued_at,envelope,actor,reason FROM never_ban_revisions WHERE revision=?", strconv.FormatUint(revision, 10))
	}
	if err != nil {
		return result, err
	}
	if !found {
		return result, ErrNeverBanMissing
	}
	rev, err := strconv.ParseUint(row[0], 10, 64)
	if err != nil || rev == 0 || rev > math.MaxInt64 {
		return result, errors.New("invalid stored never-ban revision")
	}
	issued, err := time.Parse(time.RFC3339Nano, row[1])
	if err != nil {
		return result, err
	}
	wire, err := protocol.DecodeSignedNeverBanList([]byte(row[2]))
	if err != nil {
		return result, err
	}
	list, err := protocol.VerifyNeverBanList(wire, keys, rev-1, issued)
	if err != nil {
		return result, fmt.Errorf("verify stored never-ban revision: %w", err)
	}
	if list.Revision != rev || !list.IssuedAt.Equal(issued) {
		return result, errors.New("stored never-ban metadata disagrees with signed payload")
	}
	return NeverBanRevision{List: list, Envelope: wire, Actor: row[3], Reason: row[4]}, nil
}

// ReadNeverBanRevision is read-only; revision zero selects the latest.
func (s *DB) ReadNeverBanRevision(revision uint64, keys map[string]ed25519.PublicKey) (NeverBanRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readNeverBanRevision(revision, keys)
}

func validNeverBanMetadata(value string, max int) bool {
	if strings.TrimSpace(value) != value || len(value) == 0 || len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// UpdateNeverBan appends a signed revision and its audit metadata atomically.
// With renew=true, membership is unchanged; otherwise at least one genuinely
// new entry is required. A separate fleet-protection signer is expected.
// BEGIN IMMEDIATE serializes writers even across independent CLI processes.
func (s *DB) UpdateNeverBan(additions []protocol.Protection, renew bool, actor, reason, keyID string, key ed25519.PrivateKey, now time.Time, ttl time.Duration) (NeverBanRevision, error) {
	var result NeverBanRevision
	if !validNeverBanMetadata(actor, 128) || !validNeverBanMetadata(reason, 512) {
		return result, errors.New("bounded operator identity and nonempty reason required")
	}
	if len(key) != ed25519.PrivateKeySize || now.IsZero() || ttl <= 0 || ttl > protocol.MaxNeverBanTTL {
		return result, errors.New("invalid never-ban signing key, time or TTL")
	}
	if (renew && len(additions) != 0) || (!renew && len(additions) == 0) || len(additions) > protocol.MaxNeverBanEntries {
		return result, errors.New("renew requires no entries; add requires bounded nonempty entries")
	}
	keys := map[string]ed25519.PublicKey{keyID: key.Public().(ed25519.PublicKey)}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.transaction(func() error {
		prior, err := s.readNeverBanRevision(0, keys)
		if err != nil && !errors.Is(err, ErrNeverBanMissing) {
			return err
		}
		if renew && errors.Is(err, ErrNeverBanMissing) {
			return ErrNeverBanMissing
		}
		if prior.List.Revision >= math.MaxInt64 || now.Before(prior.List.IssuedAt) {
			return errors.New("never-ban revision overflow or clock rollback")
		}
		next := protocol.NeverBanList{
			Schema:    protocol.SchemaVersion,
			Revision:  prior.List.Revision + 1,
			IssuedAt:  now.UTC(),
			ExpiresAt: now.Add(ttl).UTC(),
			Entries:   append(make([]protocol.Protection, 0, len(prior.List.Entries)+len(additions)), prior.List.Entries...),
			KeyID:     keyID,
		}
		seen := make(map[protocol.Protection]bool, len(next.Entries))
		for _, entry := range next.Entries {
			seen[entry] = true
		}
		for _, entry := range additions {
			if seen[entry] {
				continue
			}
			seen[entry] = true
			next.Entries = append(next.Entries, entry)
		}
		if !renew && len(next.Entries) == len(prior.List.Entries) {
			return errors.New("no new protections; use renew to refresh validity")
		}
		wire, err := protocol.SignNeverBanList(next, key)
		if err != nil {
			return err
		}
		next, err = protocol.VerifyNeverBanUpdate(wire, keys, prior.List, now)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(wire)
		if err != nil {
			return err
		}
		_, err = s.exec("INSERT INTO never_ban_revisions(revision,issued_at,envelope,actor,reason) VALUES(?,?,?,?,?)", strconv.FormatUint(next.Revision, 10), instant(next.IssuedAt), string(raw), actor, reason)
		if err != nil {
			return err
		}
		result = NeverBanRevision{List: next, Envelope: wire, Actor: actor, Reason: reason}
		return nil
	})
	if err != nil {
		return NeverBanRevision{}, err
	}
	return result, nil
}

// NeverBanDiff compares an authenticated historical revision to an authenticated
// current revision. Its result cannot authorize removal or enforcement.
func NeverBanDiff(previous, current protocol.NeverBanList) ([]protocol.Protection, error) {
	if err := protocol.ValidateNeverBanTransition(previous, current); err != nil {
		return nil, err
	}
	seen := make(map[protocol.Protection]bool, len(previous.Entries))
	for _, entry := range previous.Entries {
		seen[entry] = true
	}
	added := make([]protocol.Protection, 0)
	for _, entry := range current.Entries {
		if !seen[entry] {
			added = append(added, entry)
		}
	}
	return added, nil
}
