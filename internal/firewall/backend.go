// Package firewall defines the narrow contract for agent-owned, scoped
// desired-state reconciliation. An implementation must NEVER assume a remote
// decision overrides local management protections. Real adapters must enforce
// those protections independently before changing any firewall configuration.
package firewall

import (
	"context"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// Capabilities must describe what the backend demonstrably supports.
// A simulated backend must not claim real firewall enforcement.
type Capabilities struct {
	IPv4             bool
	IPv6             bool
	ScopedPorts      bool
	ForwardedTraffic bool
	KernelExpiry     bool
	Simulated        bool
}

// AppliedState represents only decisions owned by this backend, never host
// firewall rules belonging to any other tool. For a mock, Simulated is true.
type AppliedState struct {
	ObservedAt time.Time           `json:"observed_at"`
	Decisions  []protocol.Decision `json:"decisions"`
	Simulated  bool                `json:"simulated"`
}

// Backend operations are idempotent, bounded and context aware. Reconcile
// replaces the entire backend-owned desired state; it is not an append or a
// generic command execution interface.
type Backend interface {
	Capabilities(ctx context.Context) (Capabilities, error)
	Reconcile(ctx context.Context, desired []protocol.Decision) (AppliedState, error)
	Inspect(ctx context.Context) (AppliedState, error)
	RemoveOwned(ctx context.Context) error
}
