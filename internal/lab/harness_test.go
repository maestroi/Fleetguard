package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var fixedTime = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func readFixture(t *testing.T, node string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "synthetic", "node-"+node+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPartitionIdentityAndReplay(t *testing.T) {
	clock := NewClock(fixedTime)
	h, err := New(clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddNode("lab-node-a", bytes.NewReader(readFixture(t, "a"))); err != nil {
		t.Fatal(err)
	}
	if err := h.AddNode("lab-node-b", bytes.NewReader(readFixture(t, "b"))); err != nil {
		t.Fatal(err)
	}
	if err := h.AddNode("lab-node-b", bytes.NewReader(readFixture(t, "b"))); err == nil {
		t.Fatal("duplicate node added")
	}
	if err := h.AddNode("lab-node-x", bytes.NewReader(readFixture(t, "b"))); err == nil {
		t.Fatal("fixture impersonated node")
	}
	if err := h.SetPartition("lab-node-c", true); err == nil {
		t.Fatal("unknown partition accepted")
	}
	if err := h.SetPartition("lab-node-b", true); err != nil {
		t.Fatal(err)
	}
	first, err := h.Poll(context.Background(), 16)
	if err != nil || len(first) != 2 {
		t.Fatalf("first poll: %d %v", len(first), err)
	}
	for _, e := range first {
		if e.NodeID != "lab-node-a" {
			t.Fatal("partitioned event delivered")
		}
	}
	if err := h.SetPartition("lab-node-b", false); err != nil {
		t.Fatal(err)
	}
	second, err := h.Poll(context.Background(), 16)
	if err != nil || len(second) != 2 {
		t.Fatalf("second poll: %d %v", len(second), err)
	}
	for _, e := range second {
		if e.NodeID != "lab-node-b" {
			t.Fatal("wrong provenance")
		}
	}
	third, err := h.Poll(context.Background(), 16)
	if err != nil || len(third) != 0 {
		t.Fatal("events duplicated")
	}
	received := h.Received()
	if len(received) != 4 {
		t.Fatal("lost provenance")
	}
	received[0].DestinationPorts[0] = 22
	if h.Received()[0].DestinationPorts[0] != 8899 {
		t.Fatal("history aliased")
	}
}

func TestDemoIsSimulated(t *testing.T) {
	r, err := RunDemo(bytes.NewReader(readFixture(t, "a")), bytes.NewReader(readFixture(t, "b")), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != "simulated-observe-only" || r.Nodes != 2 || r.DeliveredWhilePartitioned != 2 || r.DeliveredAfterHeal != 2 || r.DistinctReportingNodes != 2 ||
		r.MockDecisionsBeforeTTL != 1 || r.MockDecisionsAfterTTL != 0 || !r.ManualMockDecision || r.RealFirewallWrites != 0 || r.NetworkListeners != 0 {
		t.Fatalf("demo must not claim real enforcement: %+v", r)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationAndConcurrency(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	clock := NewClock(fixedTime)
	h, _ := New(clock.Now)
	if _, err := h.Poll(context.Background(), 0); err == nil {
		t.Fatal("invalid batch accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Poll(ctx, 1); err != context.Canceled {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.Received(); clock.Now() }()
	}
	wg.Wait()
}

func TestInvalidFixtureAndProofSeparation(t *testing.T) {
	clock := NewClock(fixedTime)
	h, _ := New(clock.Now)
	data := readFixture(t, "a")
	var parsed struct {
		Schema int                 `json:"schema"`
		Events []protocol.Evidence `json:"events"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Events[0].ProofLevel != protocol.ProofApplicationVerified || parsed.Events[1].ProofLevel != protocol.ProofUnverifiedLog {
		t.Fatal("proof distinctions lost")
	}
	parsed.Events[0].NodeID = "lab-node-b"
	bad, _ := json.Marshal(parsed)
	if err := h.AddNode("lab-node-a", bytes.NewReader(bad)); err == nil {
		t.Fatal("spoofed fixture accepted")
	}
}
