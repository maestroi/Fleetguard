// Package synthetic consumes bounded, deterministic evidence fixtures and
// produces no real network traffic or host events.
package synthetic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const (
	MaxFixtureBytes    = 128 << 10
	MaxFixtureEvents   = 128
	MaxBatchEvents     = 16
	MaxEventsPerWindow = 32
	RateWindow         = time.Second
)

var ErrNoClock = errors.New("synthetic sensor: injected clock is required")

// Sensor has a bounded fixture, a fixed authenticated node identity and an
// injected-clock rate window. Nothing is queued in the background.
type Sensor struct {
	mu          sync.Mutex
	nodeID      string
	now         func() time.Time
	events      []protocol.Evidence
	index       int
	windowStart time.Time
	used        int
}

// Load consumes at most MaxFixtureBytes+1 bytes and rejects unrecognized
// fields, duplicate event IDs and mismatched node IDs. The caller supplies
// the trusted node identity: a fixture cannot impersonate another node.
func Load(r io.Reader, nodeID string, now func() time.Time) (*Sensor, error) {
	if now == nil {
		return nil, ErrNoClock
	}
	if r == nil {
		return nil, errors.New("synthetic sensor: fixture reader is required")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxFixtureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read fixture: %w", err)
	}
	if len(raw) > MaxFixtureBytes {
		return nil, fmt.Errorf("fixture exceeds %d bytes", MaxFixtureBytes)
	}
	var fixture struct {
		Schema int               `json:"schema"`
		Events []json.RawMessage `json:"events"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return nil, fmt.Errorf("parse synthetic fixture: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("synthetic fixture contains trailing data")
	}
	if fixture.Schema != protocol.SchemaVersion || fixture.Events == nil {
		return nil, errors.New("synthetic fixture must contain schema 1 and events array")
	}
	if len(fixture.Events) > MaxFixtureEvents {
		return nil, fmt.Errorf("fixture exceeds %d events", MaxFixtureEvents)
	}
	start := now()
	events := make([]protocol.Evidence, 0, len(fixture.Events))
	seen := make(map[string]struct{}, len(fixture.Events))
	for i, rawEvent := range fixture.Events {
		e, err := protocol.DecodeEvidence(rawEvent, nodeID, start)
		if err != nil {
			return nil, fmt.Errorf("fixture event %d: %w", i, err)
		}
		if _, exists := seen[e.EventID]; exists {
			return nil, fmt.Errorf("duplicate event ID %q", e.EventID)
		}
		seen[e.EventID] = struct{}{}
		events = append(events, clone(e))
	}
	return &Sensor{nodeID: nodeID, now: now, events: events, windowStart: start}, nil
}

func (s *Sensor) NodeID() string { return s.nodeID }

// Next returns no more than max events and no more than the per-window budget.
// Exhausted rate budget returns an empty slice (never sleeps). A future call
// after the injected clock advances resumes delivery. A canceled call never
// consumes events. Every returned event has independent port-slice storage.
func (s *Sensor) Next(ctx context.Context, max int) ([]protocol.Evidence, error) {
	if max <= 0 || max > MaxBatchEvents {
		return nil, fmt.Errorf("synthetic sensor: batch size must be 1..%d", MaxBatchEvents)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.now()
	if now.Before(s.windowStart) {
		return nil, errors.New("synthetic sensor: clock moved backwards")
	}
	if now.Sub(s.windowStart) >= RateWindow {
		s.windowStart, s.used = now, 0
	}
	remaining := len(s.events) - s.index
	quota := MaxEventsPerWindow - s.used
	if n := min(max, quota, remaining); n < max {
		max = n
	}
	out := make([]protocol.Evidence, 0, max)
	for i := 0; i < max; i++ {
		e := s.events[s.index+i]
		// Do not deliver evidence that became stale while disconnected.
		if err := protocol.ValidateEvidence(e, s.nodeID, now); err != nil {
			return nil, fmt.Errorf("synthetic sensor: stale fixture event: %w", err)
		}
		out = append(out, clone(e))
	}
	s.index += len(out)
	s.used += len(out)
	return out, nil
}

func (s *Sensor) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events) - s.index
}

func clone(e protocol.Evidence) protocol.Evidence {
	e.DestinationPorts = append([]uint16(nil), e.DestinationPorts...)
	return e
}
