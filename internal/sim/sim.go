// Package sim implements a no-network, no-privilege bootstrap smoke path.
// It does not perform threat detection or create firewall rules.
package sim

import (
	"encoding/json"
	"io"

	"github.com/maestroi/Fleetguard/internal/config"
)

type AgentStatus struct {
	Component          string `json:"component"`
	NodeID             string `json:"node_id"`
	Mode               string `json:"mode"`
	FirewallBackend    string `json:"firewall_backend"`
	EnforcementEnabled bool   `json:"enforcement_enabled"`
	EventsGenerated    int    `json:"events_generated"`
}

func Agent(c config.Agent, out io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(AgentStatus{
		Component:       "fleetguard-agent",
		NodeID:          c.NodeID,
		Mode:            c.Mode,
		FirewallBackend: c.FirewallBackend,
	})
}

type ControllerStatus struct {
	Component          string `json:"component"`
	Mode               string `json:"mode"`
	NetworkListeners   int    `json:"network_listeners"`
	PoliciesIssued     int    `json:"policies_issued"`
	EnforcementEnabled bool   `json:"enforcement_enabled"`
}

func Controller(c config.Controller, out io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(ControllerStatus{
		Component: "fleetguard-controller",
		Mode:      c.Mode,
	})
}
