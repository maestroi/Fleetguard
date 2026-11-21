//go:build linux && cgo

// Package store provides a small, serialized SQLite store for the lab controller.
// SQLite is accessed using the system libsqlite3; no SQL input is constructed
// from untrusted values. All user values are bound as prepared parameters.
package store

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var ErrConflict = errors.New("event id or dedup key reused with different payload")
var ErrCapacity = errors.New("evidence retention capacity reached")
var ErrRevision = errors.New("acknowledgement does not match current policy revision")

// DB keeps one connection and serializes transactions; small lab workloads only.
type DB struct {
	mu sync.Mutex
	db *C.sqlite3
}

func Open(path string) (*DB, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("a private SQLite file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if dir.Mode().Perm()&0077 != 0 {
		return nil, errors.New("SQLite parent directory must be private (chmod 700)")
	}
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode().Perm()&0077 != 0 {
			return nil, errors.New("existing SQLite file must be private regular file (chmod 600)")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	if rc := C.sqlite3_open_v2(cpath, &db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil); rc != C.SQLITE_OK {
		message := "sqlite open failed"
		if db != nil {
			message = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return nil, errors.New(message)
	}
	C.sqlite3_busy_timeout(db, 2000)
	s := &DB{db: db}
	for _, sql := range []string{
		`PRAGMA journal_mode=DELETE`,
		`CREATE TABLE IF NOT EXISTS evidence (node_id TEXT NOT NULL, event_id TEXT NOT NULL, dedup_key TEXT NOT NULL, group_id TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL, received_at TEXT NOT NULL, PRIMARY KEY(node_id,event_id), UNIQUE(node_id,dedup_key))`,
		`CREATE INDEX IF NOT EXISTS evidence_group_received_idx ON evidence(group_id,received_at)`,
		`CREATE TABLE IF NOT EXISTS snapshots (node_id TEXT NOT NULL, group_id TEXT NOT NULL, revision INTEGER NOT NULL, expires_at TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(node_id,group_id))`,
		`CREATE TABLE IF NOT EXISTS acks (node_id TEXT NOT NULL, group_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL, received_at TEXT NOT NULL, PRIMARY KEY(node_id,group_id,revision,state))`,
		`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, kind TEXT NOT NULL, node_id TEXT NOT NULL, detail TEXT NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS audit_bounded AFTER INSERT ON audit BEGIN DELETE FROM audit WHERE id <= (SELECT MAX(id) - 20000 FROM audit); END;`,
	} {
		if _, err := s.exec(sql); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}
func (s *DB) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	if C.sqlite3_close(s.db) != C.SQLITE_OK {
		return errors.New("sqlite close failed")
	}
	s.db = nil
	return nil
}

// prepare and bind all parameters as UTF-8 text (never string-concatenate SQL).
func (s *DB) prepare(query string, args []string) (*C.sqlite3_stmt, error) {
	q := C.CString(query)
	defer C.free(unsafe.Pointer(q))
	var stmt *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(s.db, q, -1, &stmt, nil) != C.SQLITE_OK {
		return nil, fmt.Errorf("sqlite prepare: %s", C.GoString(C.sqlite3_errmsg(s.db)))
	}
	for i, v := range args {
		ptr := C.CString(v)
		rc := C.sqlite3_bind_text(stmt, C.int(i+1), ptr, C.int(len(v)), C.SQLITE_TRANSIENT)
		C.free(unsafe.Pointer(ptr))
		if rc != C.SQLITE_OK {
			C.sqlite3_finalize(stmt)
			return nil, fmt.Errorf("sqlite bind: %s", C.GoString(C.sqlite3_errmsg(s.db)))
		}
	}
	return stmt, nil
}
func (s *DB) exec(query string, args ...string) (int, error) {
	stmt, err := s.prepare(query, args)
	if err != nil {
		return 0, err
	}
	defer C.sqlite3_finalize(stmt)
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return 0, fmt.Errorf("sqlite exec: %s", C.GoString(C.sqlite3_errmsg(s.db)))
		}
	}
	return int(C.sqlite3_changes(s.db)), nil
}
func (s *DB) row(query string, args ...string) ([]string, bool, error) {
	stmt, err := s.prepare(query, args)
	if err != nil {
		return nil, false, err
	}
	defer C.sqlite3_finalize(stmt)
	switch C.sqlite3_step(stmt) {
	case C.SQLITE_DONE:
		return nil, false, nil
	case C.SQLITE_ROW:
		n := int(C.sqlite3_column_count(stmt))
		values := make([]string, n)
		for i := range values {
			p := C.sqlite3_column_text(stmt, C.int(i))
			if p != nil {
				values[i] = C.GoString((*C.char)(unsafe.Pointer(p)))
			}
		}
		return values, true, nil
	default:
		return nil, false, fmt.Errorf("sqlite query: %s", C.GoString(C.sqlite3_errmsg(s.db)))
	}
}
func (s *DB) transaction(fn func() error) (err error) {
	if _, err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.exec("ROLLBACK")
		} else {
			_, err = s.exec("COMMIT")
		}
	}()
	return fn()
}
func instant(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func (s *DB) Audit(kind, node, detail string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), kind, node, detail)
	return err
}

// Ingest atomically persists validated evidence and its audit record.
// Duplicate retries with identical data are idempotent, including after restart.
func (s *DB) Ingest(e protocol.Evidence, group string, now time.Time) (duplicate bool, err error) {
	b, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(b)
	h := hex.EncodeToString(digest[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.transaction(func() error {
		// Bound retained evidence by age and by per-node cardinality.
		if _, err := s.exec("DELETE FROM evidence WHERE received_at < ?", now.Add(-24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		row, found, err := s.row("SELECT digest FROM evidence WHERE node_id=? AND (event_id=? OR dedup_key=?) LIMIT 1", e.NodeID, e.EventID, e.DedupKey)
		if err != nil {
			return err
		}
		if found {
			if row[0] != h {
				return ErrConflict
			}
			duplicate = true
			return nil
		}
		countRow, _, err := s.row("SELECT COUNT(*) FROM evidence WHERE node_id=?", e.NodeID)
		if err != nil {
			return err
		}
		count, err := strconv.Atoi(countRow[0])
		if err != nil {
			return err
		}
		if count >= 4096 {
			return ErrCapacity
		}

		_, err = s.exec("INSERT INTO evidence(node_id,event_id,dedup_key,group_id,payload,digest,received_at) VALUES(?,?,?,?,?,?,?)", e.NodeID, e.EventID, e.DedupKey, group, string(b), h, now.UTC().Format(time.RFC3339))
		if err != nil {
			return err
		}
		_, err = s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), "evidence_accepted", e.NodeID, group)
		return err
	})
	return duplicate, err
}

// Snapshot returns an idempotent signed *empty* desired-state snapshot for the
// authenticated node/group. It does not convert evidence into a ban.
func (s *DB) Snapshot(node, group, keyID string, key ed25519.PrivateKey, now time.Time) (protocol.SignedSnapshot, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var envelope protocol.SignedSnapshot
	var revision uint64
	err := s.transaction(func() error {
		row, found, err := s.row("SELECT revision,expires_at,envelope FROM snapshots WHERE node_id=? AND group_id=?", node, group)
		if err != nil {
			return err
		}
		if found {
			rev, err := strconv.ParseUint(row[0], 10, 64)
			if err != nil {
				return err
			}
			revision = rev
			expires, err := time.Parse(time.RFC3339Nano, row[1])
			if err != nil {
				return err
			}
			if now.Before(expires) {
				if err := json.Unmarshal([]byte(row[2]), &envelope); err != nil {
					return err
				}
				return nil
			}
		}
		if revision == ^uint64(0) {
			return errors.New("snapshot revision overflow")
		}
		revision++
		snap := protocol.Snapshot{Schema: protocol.SchemaVersion, Revision: revision, IssuedAt: now.UTC(), ExpiresAt: now.Add(2 * time.Minute).UTC(), Audience: protocol.Audience{ServiceGroup: group, NodeID: node}, Decisions: []protocol.Decision{}, KeyID: keyID}
		envelope, err = protocol.SignSnapshot(snap, key)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		_, err = s.exec("INSERT INTO snapshots(node_id,group_id,revision,expires_at,envelope) VALUES(?,?,?,?,?) ON CONFLICT(node_id,group_id) DO UPDATE SET revision=excluded.revision,expires_at=excluded.expires_at,envelope=excluded.envelope", node, group, strconv.FormatUint(revision, 10), instant(snap.ExpiresAt), string(raw))
		if err != nil {
			return err
		}
		_, err = s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), "policy_published", node, group+" revision="+strconv.FormatUint(revision, 10))
		return err
	})
	return envelope, revision, err
}

func (s *DB) Acknowledge(node, group string, a protocol.Acknowledgement, now time.Time) (duplicate bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.transaction(func() error {
		row, found, err := s.row("SELECT revision FROM snapshots WHERE node_id=? AND group_id=?", node, group)
		if err != nil {
			return err
		}
		if !found || row[0] != strconv.FormatUint(a.Revision, 10) {
			return ErrRevision
		}
		changes, err := s.exec("INSERT OR IGNORE INTO acks(node_id,group_id,revision,state,reason,received_at) VALUES(?,?,?,?,?,?)", node, group, strconv.FormatUint(a.Revision, 10), string(a.State), string(a.Reason), instant(now))
		if err != nil {
			return err
		}
		duplicate = changes == 0
		if !duplicate {
			_, err = s.exec("INSERT INTO audit(received_at,kind,node_id,detail) VALUES(?,?,?,?)", instant(now), "policy_ack", node, group+" revision="+strconv.FormatUint(a.Revision, 10)+" state="+string(a.State))
		}
		return err
	})
	return duplicate, err
}

func (s *DB) EventCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.row("SELECT COUNT(*) FROM evidence")
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return strconv.Atoi(r[0])
}
func (s *DB) AuditCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok, err := s.row("SELECT COUNT(*) FROM audit")
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return strconv.Atoi(r[0])
}

// GroupEvidence reads a strictly bounded set of authenticated, durable event
// records for an operator-only offline evaluation. It never silently truncates
// an over-capacity group: partial promotion would be unsafe.
func (s *DB) GroupEvidence(group string, since time.Time, limit int) ([]protocol.Evidence, error) {
	if group == "" || limit < 1 || limit > 4096 {
		return nil, errors.New("invalid evidence group or capacity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stmt, err := s.prepare(`SELECT payload FROM evidence WHERE group_id=? AND received_at>=? ORDER BY received_at DESC,node_id,event_id LIMIT ?`, []string{group, instant(since), strconv.Itoa(limit + 1)})
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(stmt)
	result := make([]protocol.Evidence, 0)
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return nil, fmt.Errorf("sqlite group evidence: %s", C.GoString(C.sqlite3_errmsg(s.db)))
		}
		if len(result) >= limit {
			return nil, errors.New("evidence group exceeds evaluation capacity")
		}
		ptr := C.sqlite3_column_text(stmt, 0)
		if ptr == nil {
			return nil, errors.New("stored evidence payload is NULL")
		}
		var e protocol.Evidence
		if err := json.Unmarshal([]byte(C.GoString((*C.char)(unsafe.Pointer(ptr)))), &e); err != nil {
			return nil, fmt.Errorf("malformed stored evidence: %w", err)
		}
		result = append(result, e)
	}
	return result, nil
}

// AuditEvaluation records an operator's observe-only evaluation without
// revealing bearer tokens or signing keys. A failed evaluation also audits.
func (s *DB) AuditEvaluation(group string, count int, reason string, now time.Time) error {
	if len(group) > 128 || len(reason) > 64 {
		return errors.New("invalid evaluation audit metadata")
	}
	return s.Audit("correlation_evaluation", "operator", fmt.Sprintf("group=%s candidates=%d result=%s", group, count, reason), now)
}

// AuditCandidate stores a bounded, local-only reason trail for a simulated
// candidate. This does not write to signed snapshots or firewalls.
func (s *DB) AuditCandidate(group string, d protocol.Decision, status, reason string, now time.Time) error {
	if len(group) > 128 || len(status) > 32 || len(reason) > 64 || len(d.Source) > 64 || len(d.Service) > 128 || len(d.DestinationPorts) != 1 {
		return errors.New("invalid correlation candidate audit")
	}
	detail := fmt.Sprintf("group=%s source=%s service=%s transport=%s port=%d status=%s reason=%s", group, d.Source, d.Service, d.Transport, d.DestinationPorts[0], status, reason)
	return s.Audit("correlation_candidate", "operator", detail, now)
}
