package synthetic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

var fixedTime = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func event(i int) protocol.Evidence {
	return protocol.Evidence{Schema: 1, EventID: fmt.Sprintf("event-%03d", i), NodeID: "lab-node-a", DedupKey: fmt.Sprintf("key-%03d", i),
		ObservedAt: fixedTime.Add(-10 * time.Second), WindowSeconds: 30, SourceIP: "203.0.113.42", Service: "public-rpc", Transport: protocol.TransportTCP,
		DestinationPorts: []uint16{8899}, Observation: "application_abuse", Attempts: 3, ProofLevel: protocol.ProofApplicationVerified}
}
func fixture(events ...protocol.Evidence) []byte {
	b, err := json.Marshal(struct {
		Schema int                 `json:"schema"`
		Events []protocol.Evidence `json:"events"`
	}{1, events})
	if err != nil {
		panic(err)
	}
	return b
}
func TestBoundedRateAndDefensiveCopies(t *testing.T) {
	c := &clock{t: fixedTime}
	events := make([]protocol.Evidence, 40)
	for i := range events {
		events[i] = event(i)
	}
	s, err := Load(bytes.NewReader(fixture(events...)), "lab-node-a", c.now)
	if err != nil {
		t.Fatal(err)
	}
	if s.NodeID() != "lab-node-a" {
		t.Fatal("wrong bound identity")
	}
	ctx := context.Background()
	count := 0
	for i := 0; i < 3; i++ {
		batch, err := s.Next(ctx, MaxBatchEvents)
		if err != nil {
			t.Fatal(err)
		}
		count += len(batch)
		if i == 0 {
			batch[0].DestinationPorts[0] = 22
		}
	}
	if count != MaxEventsPerWindow || s.Remaining() != 8 {
		t.Fatalf("rate not bounded: delivered=%d remaining=%d", count, s.Remaining())
	}
	batch, err := s.Next(ctx, MaxBatchEvents)
	if err != nil || len(batch) != 0 {
		t.Fatalf("budget exceeded: %d %v", len(batch), err)
	}
	c.advance(RateWindow)
	batch, err = s.Next(ctx, MaxBatchEvents)
	if err != nil || len(batch) != 8 || s.Remaining() != 0 {
		t.Fatalf("rate window did not reset: %d %v", len(batch), err)
	}
}

func TestFixtureRejectsUnsafeOrUnboundedInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		node string
	}{
		{"missing_clock_data", []byte(`{}`), "lab-node-a"},
		{"huge_bytes", bytes.Repeat([]byte("x"), MaxFixtureBytes+1), "lab-node-a"},
		{"unknown_wrapper", []byte(`{"schema":1,"events":[],"script":"echo hi"}`), "lab-node-a"},
		{"trailing", []byte(`{"schema":1,"events":[]} {}`), "lab-node-a"},
		{"wrong_schema", []byte(`{"schema":2,"events":[]}`), "lab-node-a"},
		{"null_events", []byte(`{"schema":1,"events":null}`), "lab-node-a"},
		{"spoofed_node", fixture(event(1)), "lab-node-b"},
		{"duplicate_events", fixture(event(1), event(1)), "lab-node-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(bytes.NewReader(tc.data), tc.node, func() time.Time { return fixedTime }); err == nil {
				t.Fatal("unsafe fixture accepted")
			}
		})
	}
	large := make([]protocol.Evidence, MaxFixtureEvents+1)
	for i := range large {
		large[i] = event(i)
	}
	if _, err := Load(bytes.NewReader(fixture(large...)), "lab-node-a", func() time.Time { return fixedTime }); err == nil {
		t.Fatal("unbounded events accepted")
	}
	if _, err := Load(bytes.NewReader(fixture(event(1))), "lab-node-a", nil); !errors.Is(err, ErrNoClock) {
		t.Fatal(err)
	}
	if _, err := Load(nil, "lab-node-a", func() time.Time { return fixedTime }); err == nil {
		t.Fatal("nil reader accepted")
	}
}

func TestCancellationStalenessAndValidation(t *testing.T) {
	c := &clock{t: fixedTime}
	s, err := Load(strings.NewReader(string(fixture(event(1)))), "lab-node-a", c.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Next(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.Remaining() != 1 {
		t.Fatal("canceled read consumed evidence")
	}
	if _, err := s.Next(context.Background(), 0); err == nil {
		t.Fatal("zero batch accepted")
	}
	if _, err := s.Next(context.Background(), MaxBatchEvents+1); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	c.advance(protocol.MaxEventAge + time.Minute)
	if _, err := s.Next(context.Background(), 1); err == nil {
		t.Fatal("stale event delivered")
	}
	if s.Remaining() != 1 {
		t.Fatal("stale event was consumed")
	}
	c.advance(-protocol.MaxEventAge - 2*time.Minute)
	if _, err := s.Next(context.Background(), 1); err == nil {
		t.Fatal("rewound clock accepted")
	}
}
