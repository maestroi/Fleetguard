// Package api is the explicitly enabled, observe-only HTTPS lab controller.
// It never infers a node's identity, group or service permission from JSON.
package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const MaxBodyBytes = protocol.MaxEnvelopeBytes + 1
const QueueCapacity = 64

type Server struct {
	registry   auth.Registry
	registryMu sync.RWMutex
	rateMu     sync.Mutex
	rates      map[string]rateBucket
	db         *store.DB
	keyID      string
	signingKey ed25519.PrivateKey
	now        func() time.Time
	queue      chan ingestRequest
	log        *slog.Logger
}
type rateBucket struct {
	at   time.Time
	used int
}

type ingestRequest struct {
	e      protocol.Evidence
	group  string
	result chan ingestResult
}
type ingestResult struct {
	duplicate bool
	err       error
}

// New creates a controller with a bounded, single-writer evidence queue.
// The caller owns db and should cancel the worker on shutdown.
func New(r auth.Registry, db *store.DB, keyID string, key ed25519.PrivateKey, clock func() time.Time, logger *slog.Logger) *Server {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{registry: r, db: db, keyID: keyID, signingKey: key, now: clock, queue: make(chan ingestRequest, QueueCapacity), log: logger, rates: make(map[string]rateBucket)}
}

// RunWriter must run in one goroutine until the context is cancelled.
func (s *Server) RunWriter(ctxDone <-chan struct{}) {
	for {
		select {
		case <-ctxDone:
			return
		case item := <-s.queue:
			d, err := s.db.Ingest(item.e, item.group, s.now())
			item.result <- ingestResult{d, err}
		}
	}
}

func jsonResult(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, code string) {
	jsonResult(w, status, map[string]string{"error": code})
}

// Handler has no unauthenticated endpoints; even health requires a lab node.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/evidence", s.evidence)
	mux.HandleFunc("GET /v1/snapshot", s.snapshot)
	mux.HandleFunc("POST /v1/ack", s.ack)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		// A real TLS connection is mandatory; httptest's TLS server sets this.
		if r.TLS == nil {
			problem(w, 426, "tls_required")
			return
		}
		registry := s.currentRegistry()
		n, ok := registry.Authenticate(r.Header.Get("X-Fleetguard-Node-ID"), r.Header.Get("Authorization"))
		if !ok {
			s.log.Warn("authentication rejected", "remote", r.RemoteAddr)
			problem(w, 401, "unauthorized")
			return
		}
		group := r.URL.Query().Get("group")
		if r.URL.Query().Has("group") && !registry.CanAccess(n, group, "") {
			s.log.Warn("scope rejected", "node", n.NodeID, "group", group)
			problem(w, 403, "scope_mismatch")
			return
		}
		r = r.WithContext(withIdentity(r.Context(), identity{node: n, group: group}))
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, 200, map[string]any{"status": "ok", "mode": "observe", "enforcement_enabled": false})
}
func requestGroup(w http.ResponseWriter, r *http.Request) (identity, bool) {
	id := fromIdentity(r.Context())
	if id.group == "" {
		problem(w, 400, "group_required")
		return id, false
	}
	return id, true
}

func (s *Server) evidence(w http.ResponseWriter, r *http.Request) {
	id, ok := requestGroup(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		problem(w, 415, "content_type_required")
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxEventBytes+1))
	if err != nil {
		problem(w, 400, "bad_body")
		return
	}
	if len(b) > protocol.MaxEventBytes {
		problem(w, 413, "body_too_large")
		return
	}
	now := s.now()
	ev, err := protocol.DecodeEvidence(b, id.node.NodeID, now)
	if err != nil {
		s.log.Warn("invalid evidence", "node", id.node.NodeID, "reason", protocol.Reason(err))
		problem(w, 422, string(protocol.Reason(err)))
		return
	}
	if !s.currentRegistry().CanAccess(id.node, id.group, ev.Service) {
		problem(w, 403, "service_scope_mismatch")
		return
	}
	if !s.allowEvidence(id.node.NodeID, now) {
		w.Header().Set("Retry-After", "1")
		problem(w, 429, "node_rate_limit")
		return
	}
	req := ingestRequest{e: ev, group: id.group, result: make(chan ingestResult, 1)}
	select {
	case s.queue <- req:
	default:
		problem(w, 503, "ingest_queue_full")
		return
	}
	select {
	case result := <-req.result:
		if errors.Is(result.err, store.ErrCapacity) {
			problem(w, 429, "storage_capacity")
			return
		}
		if errors.Is(result.err, store.ErrConflict) {
			problem(w, 409, "dedup_conflict")
			return
		}
		if result.err != nil {
			s.log.Error("evidence insert failed", "error", result.err)
			problem(w, 503, "storage_unavailable")
			return
		}
		jsonResult(w, 200, map[string]any{"accepted": true, "duplicate": result.duplicate})
	case <-r.Context().Done():
		return
	}
}
func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := requestGroup(w, r)
	if !ok {
		return
	}
	envelope, revision, err := s.db.Snapshot(id.node.NodeID, id.group, s.keyID, s.signingKey, s.now())
	if err != nil {
		s.log.Error("snapshot failed", "error", err)
		problem(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("X-Fleetguard-Revision", fmt.Sprint(revision))
	jsonResult(w, 200, envelope)
}
func (s *Server) ack(w http.ResponseWriter, r *http.Request) {
	id, ok := requestGroup(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		problem(w, 415, "content_type_required")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, (4<<10)+1))
	if err != nil {
		problem(w, 400, "bad_body")
		return
	}
	if len(data) > 4<<10 {
		problem(w, 413, "body_too_large")
		return
	}
	a, err := protocol.DecodeAcknowledgement(data)
	if err != nil {
		problem(w, 422, string(protocol.Reason(err)))
		return
	}
	if a.NodeID != id.node.NodeID {
		problem(w, 403, "node_scope_mismatch")
		return
	}
	duplicate, err := s.db.Acknowledge(id.node.NodeID, id.group, a, s.now())
	if errors.Is(err, store.ErrRevision) {
		problem(w, 409, "unknown_revision")
		return
	}
	if err != nil {
		s.log.Error("ack failed", "error", err)
		problem(w, 503, "storage_unavailable")
		return
	}
	jsonResult(w, 200, map[string]any{"accepted": true, "duplicate": duplicate, "note": "client_reported_state_not_verified_enforcement"})
}

// Minimal context value keeps authenticated node and group out of request JSON.
// Uses an unexported key type so other packages cannot forge the identity.
type contextKey struct{}
type identity struct {
	node  auth.Node
	group string
}

func withIdentity(ctx context.Context, id identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}
func fromIdentity(ctx context.Context) identity {
	id, _ := ctx.Value(contextKey{}).(identity)
	return id
}

// currentRegistry returns an immutable registry snapshot. Credential changes are
// only loaded through explicitly local operator action (SIGHUP / restart).
func (s *Server) currentRegistry() auth.Registry {
	s.registryMu.RLock()
	defer s.registryMu.RUnlock()
	return s.registry
}

// ReplaceRegistry audits credential and group membership changes before making
// them effective. It never accepts an admin action over HTTP.
func (s *Server) ReplaceRegistry(next auth.Registry) error {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	oldByID := make(map[string]auth.Node, len(s.registry.Nodes))
	for _, n := range s.registry.Nodes {
		oldByID[n.NodeID] = n
	}
	nextByID := make(map[string]auth.Node, len(next.Nodes))
	for _, n := range next.Nodes {
		nextByID[n.NodeID] = n
		prev, found := oldByID[n.NodeID]
		change := ""
		switch {
		case !found:
			change = "credential_enrolled"
		case prev.TokenSHA256 != n.TokenSHA256:
			change = "credential_rotated"
		case prev.Revoked != n.Revoked:
			if n.Revoked {
				change = "credential_revoked"
			} else {
				change = "credential_restored"
			}
		case !slices.Equal(prev.Groups, n.Groups):
			change = "membership_updated"
		}
		if change != "" {
			if err := s.db.Audit(change, n.NodeID, "local_registry_reload", s.now()); err != nil {
				return err
			}
		}
	}
	for id := range oldByID {
		if _, ok := nextByID[id]; !ok {
			if err := s.db.Audit("credential_removed", id, "local_registry_reload", s.now()); err != nil {
				return err
			}
		}
	}
	if !reflect.DeepEqual(s.registry.Groups, next.Groups) {
		if err := s.db.Audit("group_policy_updated", "controller", "local_registry_reload", s.now()); err != nil {
			return err
		}
	}
	s.registry = next
	return nil
}

// allowEvidence caps each authenticated node at 32 evidence envelopes per
// one-second window. The number of buckets is bounded by registry size.
func (s *Server) allowEvidence(node string, now time.Time) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	b := s.rates[node]
	if b.at.IsZero() || now.Before(b.at) || now.Sub(b.at) >= time.Second {
		b = rateBucket{at: now}
	}
	if b.used >= 32 {
		s.rates[node] = b
		return false
	}
	b.used++
	s.rates[node] = b
	return true
}
