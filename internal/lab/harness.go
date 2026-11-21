// Package lab provides deterministic, rootless, in-process simulations.
// A partition only suppresses synthetic delivery; no network connection,
// controller API or enforcement path exists in this package.
package lab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/sensor/synthetic"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const (
	MaxNodes    = 16
	MaxReceived = MaxNodes * synthetic.MaxFixtureEvents
)

type node struct {
	sensor      *synthetic.Sensor
	partitioned bool
}

// Harness never treats a claimed proof level as authorization to issue policy.
// Delivery is an in-memory audit of received fixtures, not correlation.
type Harness struct {
	mu       sync.Mutex
	now      func() time.Time
	nodes    map[string]*node
	received []protocol.Evidence
}

func New(now func() time.Time) (*Harness, error) {
	if now == nil {
		return nil, errors.New("lab: injected clock is required")
	}
	return &Harness{now: now, nodes: make(map[string]*node)}, nil
}

func (h *Harness) AddNode(nodeID string, r io.Reader) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.nodes) >= MaxNodes {
		return fmt.Errorf("lab: at most %d nodes", MaxNodes)
	}
	if _, exists := h.nodes[nodeID]; exists {
		return fmt.Errorf("lab: duplicate node %q", nodeID)
	}
	sensor, err := synthetic.Load(r, nodeID, h.now)
	if err != nil {
		return err
	}
	h.nodes[nodeID] = &node{sensor: sensor}
	return nil
}

func (h *Harness) SetPartition(nodeID string, partitioned bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, ok := h.nodes[nodeID]
	if !ok {
		return fmt.Errorf("lab: unknown node %q", nodeID)
	}
	n.partitioned = partitioned
	return nil
}

// Poll makes one deterministic pass over nodes in stable ID order, without
// consuming messages from partitioned nodes. It reports exactly the newly
// delivered events, which are validated against their configured identity.
func (h *Harness) Poll(ctx context.Context, maxPerNode int) ([]protocol.Evidence, error) {
	if maxPerNode <= 0 || maxPerNode > synthetic.MaxBatchEvents {
		return nil, errors.New("lab: invalid maxPerNode")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(h.nodes))
	for id := range h.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]protocol.Evidence, 0, len(ids)*maxPerNode)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := h.nodes[id]
		if n.partitioned {
			continue
		}
		// The total stored history is deliberately bounded; never evict
		// silently or consume events that cannot be accounted for.
		capacity := MaxReceived - len(h.received) - len(out)
		if capacity <= 0 {
			return nil, errors.New("lab: received evidence capacity reached")
		}
		count := min(maxPerNode, capacity)
		batch, err := n.sensor.Next(ctx, count)
		if err != nil {
			return nil, fmt.Errorf("lab: node %s: %w", id, err)
		}
		for _, e := range batch {
			if err := protocol.ValidateEvidence(e, id, h.now()); err != nil {
				return nil, fmt.Errorf("lab: invalid delivered evidence: %w", err)
			}
			out = append(out, e)
		}
	}
	for _, e := range out {
		h.received = append(h.received, clone(e))
	}
	return out, nil
}

// Received is a defensive copy, preserving independent node provenance.
func (h *Harness) Received() []protocol.Evidence {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]protocol.Evidence, 0, len(h.received))
	for _, e := range h.received {
		out = append(out, clone(e))
	}
	return out
}

func clone(e protocol.Evidence) protocol.Evidence {
	e.DestinationPorts = append([]uint16(nil), e.DestinationPorts...)
	return e
}
