//go:build linux && firewalld_integration

package firewalld

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// TestDisposableVMReconcile is destructive to one explicitly named, owned
// firewalld runtime set ONLY. It must never be run on a production machine.
// It cannot prove kernel INPUT packet-path behavior: verify external traffic
// and management access separately as documented in docs/firewalld-backend.md.
func TestDisposableVMReconcile(t *testing.T) {
	if os.Getenv("FLEETGUARD_LAB_CONFIRM") != "disposable-vm-console-ready" {
		t.Skip("requires explicit disposable VM console confirmation")
	}
	required := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing %s", name)
		}
		return value
	}
	policyPath := required("FLEETGUARD_TEST_POLICY")
	zone := required("FLEETGUARD_TEST_ZONE")
	node := required("FLEETGUARD_TEST_NODE")
	group := required("FLEETGUARD_TEST_GROUP")
	service := required("FLEETGUARD_TEST_SERVICE")
	source := required("FLEETGUARD_TEST_SOURCE")
	portValue := required("FLEETGUARD_TEST_PORT")

	port, err := strconv.Atoi(portValue)
	if err != nil || port <= 0 || port > 65535 {
		t.Fatal("test port must be 1-65535")
	}
	sourcePrefix, err := netip.ParsePrefix(source)
	if err != nil || !sourcePrefix.Addr().Is4() || sourcePrefix.Bits() != 32 || sourcePrefix.Masked() != sourcePrefix {
		t.Fatal("test source must be canonical IPv4 /32")
	}
	if os.Geteuid() != 0 {
		t.Fatal("only root may exercise a real firewalld D-Bus backend")
	}
	local, err := safety.LoadRootOwned(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	bus, err := ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()

	binding := Binding{Service: service, Transport: protocol.TransportTCP, Port: uint16(port)}
	audience := protocol.Audience{NodeID: node, ServiceGroup: group}
	opts := Options{
		Zone: zone, Audience: audience, Policy: local,
		Bindings: []Binding{binding}, HostINPUTVerified: true, Now: time.Now,
	}
	backend, err := New(bus, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := backend.Capabilities(ctx); err != nil {
		t.Fatalf("refusing unsafe lab host: %v", err)
	}
	setName := SetName(zone, audience, binding)
	beforeEntries, err := bus.Entries(ctx, setName)
	if err != nil {
		t.Fatal(err)
	}
	beforeRules, err := bus.RichRules(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeEntries) != 0 || slices.Contains(beforeRules, RichRule(zone, audience, binding)) {
		t.Fatal("refusing to overwrite an already populated Fleetguard runtime set")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := backend.RemoveOwned(cleanup); err != nil {
			t.Errorf("urgent: cleanup of the owned runtime rule failed: %v", err)
		}
	}()

	now := time.Now().UTC()
	decision := protocol.Decision{
		ID: "integration-test", Source: source, Action: protocol.ActionDrop,
		Service: service, Transport: protocol.TransportTCP, DestinationPorts: []uint16{uint16(port)},
		ExpiresAt: now.Add(25 * time.Second), ReasonCode: "integration_test",
	}
	state, err := backend.Reconcile(ctx, []protocol.Decision{decision})
	if err != nil {
		t.Fatal(err)
	}
	if state.Simulated || len(state.Decisions) != 1 {
		t.Fatalf("expected one observed runtime rule: %+v", state)
	}
	observed, err := backend.Inspect(ctx)
	if err != nil || len(observed.Decisions) != 1 {
		t.Fatalf("readback failed: %+v %v", observed, err)
	}
	if err := backend.RemoveOwned(ctx); err != nil {
		t.Fatal(err)
	}
	afterEntries, err := bus.Entries(ctx, setName)
	if err != nil || len(afterEntries) != 0 {
		t.Fatalf("owned entry remains: %v %v", afterEntries, err)
	}
	afterRules, err := bus.RichRules(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(beforeRules)
	slices.Sort(afterRules)
	if !reflect.DeepEqual(beforeRules, afterRules) {
		t.Fatal(fmt.Sprintf("unrelated firewalld rules changed: before=%v after=%v", beforeRules, afterRules))
	}
}
