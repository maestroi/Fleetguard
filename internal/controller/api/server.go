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
	"strconv"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/buildinfo"
	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/internal/metrics"
	"github.com/maestroi/Fleetguard/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
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
	// Metrics use only bounded labels: route patterns, HTTP codes and fixed
	// protocol enums. Never node IDs, IPs, groups or error text.
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	rejected *prometheus.CounterVec
	acks     *prometheus.CounterVec
	storage  *prometheus.CounterVec
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
	s := &Server{registry: r, db: db, keyID: keyID, signingKey: key, now: clock, queue: make(chan ingestRequest, QueueCapacity), log: logger, rates: make(map[string]rateBucket),
		reg: metrics.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fleetguard_controller_http_requests_total",
			Help: "API requests by matched route pattern and HTTP status code."}, []string{"route", "code"}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fleetguard_controller_events_rejected_total",
			Help: "Evidence envelopes rejected after authentication, by bounded reason."}, []string{"reason"}),
		acks: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fleetguard_controller_agent_ack_total",
			Help: "Agent-reported acknowledgement states. Client-reported, not verified enforcement."}, []string{"state"}),
		storage: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fleetguard_controller_storage_errors_total",
			Help: "SQLite storage failures by operation."}, []string{"operation"}),
	}
	s.reg.MustRegister(s.requests, s.rejected, s.acks, s.storage,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "fleetguard_controller_ingest_queue_depth",
			Help: "Evidence envelopes waiting for the single SQLite writer."}, func() float64 { return float64(len(s.queue)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "fleetguard_controller_ingest_queue_capacity",
			Help: "Bounded evidence queue capacity."}, func() float64 { return QueueCapacity }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "fleetguard_controller_registered_nodes",
			Help: "Non-revoked nodes in the local registry."}, func() float64 {
			n := 0
			for _, node := range s.currentRegistry().Nodes {
				if !node.Revoked {
					n++
				}
			}
			return float64(n)
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "fleetguard_controller_enforcement_enabled",
			Help: "Always 0: the controller is observe-only and publishes empty policies."}, func() float64 { return 0 }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "fleetguard_controller_info",
			Help: "Build and mode information.", ConstLabels: prometheus.Labels{"version": buildinfo.Version, "mode": "observe"}}, func() float64 { return 1 }),
	)
	for _, v := range []prometheus.Counter{s.storage.WithLabelValues("ingest"), s.storage.WithLabelValues("snapshot"), s.storage.WithLabelValues("ack"), s.storage.WithLabelValues("audit")} {
		v.Add(0) // pre-create series so rate() and absent-alerts work from the first scrape
	}
	return s
}

// MetricsRegistry exposes the per-server registry for the separate listener.
func (s *Server) MetricsRegistry() *prometheus.Registry { return s.reg }

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
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
	mux.HandleFunc("GET /v1/audit", s.auditView)
	mux.HandleFunc("POST /v1/evidence", s.evidence)
	mux.HandleFunc("GET /v1/snapshot", s.snapshot)
	mux.HandleFunc("POST /v1/ack", s.ack)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route is a fixed mux pattern (never the raw path) to bound cardinality.
		_, route := mux.Handler(r)
		if route == "" {
			route = "unmatched"
		}
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		defer func() { s.requests.WithLabelValues(route, strconv.Itoa(rec.code)).Inc() }()
		w = rec
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
	id := fromIdentity(r.Context())
	jsonResult(w, 200, map[string]any{
		"status": "ok", "mode": "observe", "enforcement_enabled": false,
		"node_id": id.node.NodeID, "authenticated": true, "queue_depth": len(s.queue),
		"applied_state_verified": false,
	})
}

// auditView is authenticated and restricted to the *current node and group*.
// There is intentionally NO fleet-wide administrator HTTP endpoint.
func (s *Server) auditView(w http.ResponseWriter, r *http.Request) {
	id, ok := requestGroup(w, r)
	if !ok {
		return
	}
	limit := 16
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 32 {
			problem(w, 400, "invalid_audit_limit")
			return
		}
		limit = value
	}
	view, err := s.db.ReadNodeAudit(id.node.NodeID, id.group, limit)
	if err != nil {
		s.storage.WithLabelValues("audit").Inc()
		s.log.Error("audit view failed", "error", err)
		problem(w, 503, "storage_unavailable")
		return
	}
	jsonResult(w, 200, view)
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
		s.rejected.WithLabelValues(string(protocol.Reason(err))).Inc()
		problem(w, 422, string(protocol.Reason(err)))
		return
	}
	if !s.currentRegistry().CanAccess(id.node, id.group, ev.Service) {
		s.rejected.WithLabelValues("service_scope_mismatch").Inc()
		problem(w, 403, "service_scope_mismatch")
		return
	}
	if !s.allowEvidence(id.node.NodeID, now) {
		s.rejected.WithLabelValues("node_rate_limit").Inc()
		w.Header().Set("Retry-After", "1")
		problem(w, 429, "node_rate_limit")
		return
	}
	req := ingestRequest{e: ev, group: id.group, result: make(chan ingestResult, 1)}
	select {
	case s.queue <- req:
	default:
		s.rejected.WithLabelValues("ingest_queue_full").Inc()
		problem(w, 503, "ingest_queue_full")
		return
	}
	select {
	case result := <-req.result:
		if errors.Is(result.err, store.ErrCapacity) {
			s.rejected.WithLabelValues("storage_capacity").Inc()
			problem(w, 429, "storage_capacity")
			return
		}
		if errors.Is(result.err, store.ErrConflict) {
			problem(w, 409, "dedup_conflict")
			return
		}
		if result.err != nil {
			s.storage.WithLabelValues("ingest").Inc()
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
		s.storage.WithLabelValues("snapshot").Inc()
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
		s.storage.WithLabelValues("ack").Inc()
		s.log.Error("ack failed", "error", err)
		problem(w, 503, "storage_unavailable")
		return
	}
	if !duplicate {
		s.acks.WithLabelValues(string(a.State)).Inc()
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
