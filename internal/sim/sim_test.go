package sim

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/maestroi/Fleetguard/internal/config"
)

func TestAgentObserveOnly(t *testing.T) {
	var b bytes.Buffer
	c := config.Agent{NodeID: "lab-node-a", Mode: config.ModeObserve, FirewallBackend: config.BackendSimulated}
	if err := Agent(c, &b); err != nil {
		t.Fatal(err)
	}
	var status AgentStatus
	if err := json.Unmarshal(b.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.NodeID != "lab-node-a" || status.EnforcementEnabled || status.EventsGenerated != 0 || status.FirewallBackend != "simulated" {
		t.Fatalf("unexpected simulated status: %+v", status)
	}
	c.Mode = "enforce"
	if err := Agent(c, &b); err == nil {
		t.Fatal("simulator should refuse enforcement")
	}
}

func TestControllerNoNetwork(t *testing.T) {
	var b bytes.Buffer
	if err := Controller(config.Controller{Mode: config.ModeObserve}, &b); err != nil {
		t.Fatal(err)
	}
	var status ControllerStatus
	if err := json.Unmarshal(b.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.NetworkListeners != 0 || status.PoliciesIssued != 0 || status.EnforcementEnabled {
		t.Fatalf("unexpected controller status: %+v", status)
	}
}
