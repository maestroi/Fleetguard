package lab

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall/mock"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// Clock is an injection point, not a wall-clock or timer-driven scheduler.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func NewClock(at time.Time) *Clock { return &Clock{t: at} }
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *Clock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(delta)
}

type DemoReport struct {
	Mode                      string `json:"mode"`
	Nodes                     int    `json:"nodes"`
	DeliveredWhilePartitioned int    `json:"delivered_while_partitioned"`
	DeliveredAfterHeal        int    `json:"delivered_after_heal"`
	DistinctReportingNodes    int    `json:"distinct_reporting_nodes"`
	MockDecisionsBeforeTTL    int    `json:"mock_decisions_before_ttl"`
	MockDecisionsAfterTTL     int    `json:"mock_decisions_after_ttl"`
	ManualMockDecision        bool   `json:"manual_mock_decision"`
	RealFirewallWrites        int    `json:"real_firewall_writes"`
	NetworkListeners          int    `json:"network_listeners"`
}

// RunDemo is intentionally not a full controller or a policy promotion path.
// It performs a two-node deterministic fixture delivery with a partition and
// tests expiry of a manually specified, mock-only decision. It never verifies
// any remote authorization or issues a signed enforcement policy.
func RunDemo(a, b io.Reader, at time.Time) (DemoReport, error) {
	ctx := context.Background()
	clock := NewClock(at)
	h, err := New(clock.Now)
	if err != nil {
		return DemoReport{}, err
	}
	if err := h.AddNode("lab-node-a", a); err != nil {
		return DemoReport{}, err
	}
	if err := h.AddNode("lab-node-b", b); err != nil {
		return DemoReport{}, err
	}
	if err := h.SetPartition("lab-node-b", true); err != nil {
		return DemoReport{}, err
	}
	first, err := h.Poll(ctx, 16)
	if err != nil {
		return DemoReport{}, err
	}
	if err := h.SetPartition("lab-node-b", false); err != nil {
		return DemoReport{}, err
	}
	second, err := h.Poll(ctx, 16)
	if err != nil {
		return DemoReport{}, err
	}
	backend, err := mock.New(clock.Now)
	if err != nil {
		return DemoReport{}, err
	}
	// Manually authored mock-only decision; it is not inferred from events.
	state, err := backend.Reconcile(ctx, []protocol.Decision{{
		ID: "simulated-drop-1", Source: "203.0.113.42/32", Action: protocol.ActionDrop,
		Service: "public-rpc", Transport: protocol.TransportTCP,
		DestinationPorts: []uint16{8899}, ExpiresAt: at.Add(30 * time.Second),
		ReasonCode: "manual_fixture",
	}})
	if err != nil {
		return DemoReport{}, err
	}
	clock.Advance(31 * time.Second)
	after, err := backend.Inspect(ctx)
	if err != nil {
		return DemoReport{}, err
	}
	unique := make(map[string]struct{})
	for _, e := range h.Received() {
		unique[e.NodeID] = struct{}{}
	}
	return DemoReport{
		Mode: "simulated-observe-only", Nodes: 2,
		DeliveredWhilePartitioned: len(first), DeliveredAfterHeal: len(second),
		DistinctReportingNodes: len(unique), MockDecisionsBeforeTTL: len(state.Decisions),
		MockDecisionsAfterTTL: len(after.Decisions), ManualMockDecision: true,
		RealFirewallWrites: 0, NetworkListeners: 0,
	}, nil
}
