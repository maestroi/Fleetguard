// Package firewalld provides an explicitly gated, firewalld D-Bus runtime
// adapter. No host firewall is touched unless a caller constructs this backend
// with a locally approved, lab-attested INPUT configuration. The agent does
// not wire this adapter until policy reconciliation is implemented in #9.
package firewalld

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
	"github.com/maestroi/Fleetguard/internal/safety"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const (
	setPrefix        = "fg1_"
	ownedDescription = "Fleetguard runtime entries v1 "
	richPriority     = -100
	maxBindings      = 64
)

var (
	ErrUnsupported = errors.New("firewalld backend: unsupported or unverified INPUT configuration")
	ErrDrift       = errors.New("firewalld backend: live state differs from accepted desired state")
)

// Client contains only the read and write D-Bus operations this adapter needs.
// A fake client tests the same reconcile algorithm without root, a system bus,
// firewalld, a network namespace or any kernel firewall operations.
type Client interface {
	Status(context.Context) (Status, error)
	IPSetSettings(context.Context, string) (SetSettings, error)
	Entries(context.Context, string) ([]string, error)
	RichRules(context.Context, string) ([]string, error)
	AddEntry(context.Context, string, string) error
	RemoveEntry(context.Context, string, string) error
	AddRichRule(context.Context, string, string) error
	RemoveRichRule(context.Context, string, string) error
}

type Status struct {
	State       string
	Version     string
	Backend     string
	IPv4        bool
	IPSet       bool
	IPSetTypes  []string
	ActiveZones map[string]map[string][]string
}
type SetSettings struct {
	Type        string
	Description string
	Options     map[string]string
}
type Binding struct {
	Service   string
	Transport protocol.Transport
	Port      uint16
}
type Options struct {
	// Zone must cover all INPUT packet paths in the isolated test VM. Other
	// active zones and source-specific zone mappings cause refusal to enforce.
	Zone     string
	Audience protocol.Audience
	Policy   safety.Policy
	Bindings []Binding
	// This local-only acknowledgment may be set ONLY after a disposable VM
	// verifies INPUT scope, rich rule precedence and management access.
	HostINPUTVerified bool
	Now               func() time.Time
}

// SetName is derived from the full scope, making collisions between hosts,
// service groups, transports and ports difficult. It is never accepted from
// a remote payload or chosen by a controller.
func SetName(zone string, audience protocol.Audience, binding Binding) string {
	data := zone + "\x00" + audience.NodeID + "\x00" + audience.ServiceGroup + "\x00" + binding.Service + "\x00" + string(binding.Transport) + "\x00" + strconv.Itoa(int(binding.Port))
	h := sha256.Sum256([]byte(data))
	return setPrefix + hex.EncodeToString(h[:8])
}
func SetDescription(zone string, audience protocol.Audience, binding Binding) string {
	return ownedDescription + SetName(zone, audience, binding)
}
func RichRule(zone string, audience protocol.Audience, binding Binding) string {
	name := SetName(zone, audience, binding)
	return fmt.Sprintf(`rule family="ipv4" priority="%d" source ipset="%s" port port="%d" protocol="%s" drop`, richPriority, name, binding.Port, binding.Transport)
}

type Backend struct {
	mu         sync.Mutex
	bus        Client
	options    Options
	known      []protocol.Decision
	knownValid bool // false after new process until first full reconcile
}

var _ firewall.Backend = (*Backend)(nil)

func New(bus Client, o Options) (*Backend, error) {
	if bus == nil {
		return nil, errors.New("firewalld backend: D-Bus client required")
	}
	if o.Zone == "" || !validName(o.Zone) || o.Audience.NodeID == "" || o.Audience.ServiceGroup == "" {
		return nil, errors.New("firewalld backend: explicit zone and audience are required")
	}
	if err := o.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("firewalld backend: invalid local policy: %w", err)
	}
	if len(o.Bindings) == 0 || len(o.Bindings) > maxBindings {
		return nil, errors.New("firewalld backend: 1-64 explicit bindings are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	seen := map[string]bool{}
	for _, b := range o.Bindings {
		if !validName(b.Service) || (b.Transport != protocol.TransportTCP && b.Transport != protocol.TransportUDP) || b.Port == 0 {
			return nil, errors.New("firewalld backend: invalid binding")
		}
		name := SetName(o.Zone, o.Audience, b)
		if seen[name] {
			return nil, errors.New("firewalld backend: duplicate set binding")
		}
		seen[name] = true
		allowed := false
		for _, scope := range o.Policy.ServiceScopes {
			if scope.ServiceGroup != o.Audience.ServiceGroup || scope.Service != b.Service || scope.Transport != b.Transport {
				continue
			}
			for _, port := range scope.Ports {
				if port == b.Port {
					allowed = true
				}
			}
		}
		if !allowed {
			return nil, fmt.Errorf("firewalld backend: binding %s/%d outside local policy", b.Service, b.Port)
		}
	}
	return &Backend{bus: bus, options: o}, nil
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
func has(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// probe checks live D-Bus capabilities every time rather than caching a
// decision that could become unsafe after a reload or zone change.
func (b *Backend) probe(ctx context.Context) (firewall.Capabilities, error) {
	if !b.options.HostINPUTVerified {
		return firewall.Capabilities{}, fmt.Errorf("%w: operator has not attested host INPUT packet path", ErrUnsupported)
	}
	s, err := b.bus.Status(ctx)
	if err != nil {
		return firewall.Capabilities{}, fmt.Errorf("firewalld status: %w", err)
	}
	if s.State != "RUNNING" || s.Backend != "nftables" || !s.IPv4 || !s.IPSet || !has(s.IPSetTypes, "hash:ip") {
		return firewall.Capabilities{}, fmt.Errorf("%w: state/backend/IPv4/ipset support", ErrUnsupported)
	}
	// Firewalld 2.x is the tested *API family*, not proof of a supported
	// specific kernel/zone topology. That requires the separate local attestation.
	parts := strings.Split(s.Version, ".")
	if len(parts) < 2 {
		return firewall.Capabilities{}, fmt.Errorf("%w: unknown version %q", ErrUnsupported, s.Version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major != 2 {
		return firewall.Capabilities{}, fmt.Errorf("%w: unsupported version %q", ErrUnsupported, s.Version)
	}
	if len(s.ActiveZones) != 1 {
		return firewall.Capabilities{}, fmt.Errorf("%w: expected exactly one active host INPUT zone", ErrUnsupported)
	}
	zone, ok := s.ActiveZones[b.options.Zone]
	if !ok || len(zone["interfaces"]) == 0 || len(zone["sources"]) != 0 {
		return firewall.Capabilities{}, fmt.Errorf("%w: zone or source-based routing mismatch", ErrUnsupported)
	}
	for _, iface := range zone["interfaces"] {
		if !validName(iface) {
			return firewall.Capabilities{}, fmt.Errorf("%w: invalid interface binding", ErrUnsupported)
		}
	}
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		settings, err := b.bus.IPSetSettings(ctx, name)
		if err != nil {
			return firewall.Capabilities{}, fmt.Errorf("%w: set %s not pre-provisioned: %v", ErrUnsupported, name, err)
		}
		if settings.Type != "hash:ip" || settings.Description != SetDescription(b.options.Zone, b.options.Audience, binding) || settings.Options["family"] != "inet" || settings.Options["timeout"] != "" {
			return firewall.Capabilities{}, fmt.Errorf("%w: mismatched or timed set %s", ErrUnsupported, name)
		}
	}
	return firewall.Capabilities{IPv4: true, ScopedPorts: true, ForwardedTraffic: false, KernelExpiry: false, Simulated: false}, nil
}
func (b *Backend) Capabilities(ctx context.Context) (firewall.Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return firewall.Capabilities{}, err
	}
	return b.probe(ctx)
}

type observed struct {
	entries map[string]map[string]bool
	rules   map[string]bool
}

func (b *Backend) observe(ctx context.Context) (observed, error) {
	names := make(map[string]bool, len(b.options.Bindings))
	for _, binding := range b.options.Bindings {
		names[SetName(b.options.Zone, b.options.Audience, binding)] = true
	}
	rules, err := b.bus.RichRules(ctx, b.options.Zone)
	if err != nil {
		return observed{}, err
	}
	all := make(map[string]bool, len(rules))
	for _, r := range rules {
		all[r] = true
	}
	out := observed{entries: make(map[string]map[string]bool, len(names)), rules: all}
	for name := range names {
		entries, err := b.bus.Entries(ctx, name)
		if err != nil {
			return observed{}, fmt.Errorf("get entries for %s: %w", name, err)
		}
		if len(entries) > protocol.MaxDecisions {
			return observed{}, fmt.Errorf("%w: unexpected set cardinality", ErrDrift)
		}
		out.entries[name] = make(map[string]bool, len(entries))
		for _, source := range entries {
			ip, err := netip.ParseAddr(source)
			if err != nil || !ip.Is4() || ip.String() != source {
				return observed{}, fmt.Errorf("%w: noncanonical IPv4 entry in %s", ErrDrift, name)
			}
			out.entries[name][source] = true
		}
	}
	return out, nil
}

func (b *Backend) desiredEntries(decisions []protocol.Decision) (map[string]map[string]bool, error) {
	want := make(map[string]map[string]bool, len(b.options.Bindings))
	for _, binding := range b.options.Bindings {
		want[SetName(b.options.Zone, b.options.Audience, binding)] = make(map[string]bool)
	}
	for _, d := range decisions {
		prefix, err := netip.ParsePrefix(d.Source)
		if err != nil {
			return nil, err
		}
		ip := prefix.Addr().String()
		for _, port := range d.DestinationPorts {
			name := SetName(b.options.Zone, b.options.Audience, Binding{Service: d.Service, Transport: d.Transport, Port: port})
			entries, ok := want[name]
			if !ok {
				return nil, fmt.Errorf("%w: unprovisioned binding for %s/%d", ErrUnsupported, d.Service, port)
			}
			entries[ip] = true
		}
	}
	return want, nil
}
func (b *Backend) validated(ctx context.Context, decisions []protocol.Decision) ([]protocol.Decision, error) {
	if len(decisions) > protocol.MaxDecisions {
		return nil, fmt.Errorf("too many decisions")
	}
	now := b.options.Now()
	live := make([]protocol.Decision, 0, len(decisions))
	for _, d := range decisions {
		if d.ExpiresAt.After(now) {
			live = append(live, d)
		}
	}
	if len(live) == 0 {
		return live, nil
	} // empty desired is always allowed for recovery
	caps, err := b.probe(ctx)
	if err != nil {
		return nil, err
	}
	latest := now.Add(protocol.MaxSnapshotTTL)
	// This synthetic container is NOT authority. Its only purpose is to reuse
	// the local safety gate's complete, independent validation of all decisions.
	s := protocol.Snapshot{Schema: protocol.SchemaVersion, Revision: 1, IssuedAt: now, ExpiresAt: latest, Audience: b.options.Audience, Decisions: live, KeyID: "local-backend-preflight"}
	runtime := safety.Runtime{BackendName: "firewalld", Verified: b.options.HostINPUTVerified, Capabilities: caps}
	if err := b.options.Policy.Authorize(s, b.options.Audience, now, runtime); err != nil {
		return nil, err
	}
	return live, nil
}

// Reconcile only changes entries of pre-provisioned, fingerprinted Fleetguard
// IP sets and exact, generated runtime rich rules in the single attested zone.
// It never invokes firewall-cmd, touches permanent config or edits other zones.
// It uses a read/diff/write/verify pass; partial D-Bus failures return errors
// and never pretend that desired state was fully applied.
func (b *Backend) Reconcile(ctx context.Context, desired []protocol.Decision) (firewall.AppliedState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return firewall.AppliedState{}, err
	}
	live, err := b.validated(ctx, desired)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	if _, err := b.probe(ctx); err != nil {
		return firewall.AppliedState{}, err
	} // even empty removal must verify ownership
	want, err := b.desiredEntries(live)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	current, err := b.observe(ctx)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	if err := b.apply(ctx, want, current); err != nil {
		return firewall.AppliedState{}, err
	}
	actual, err := b.observe(ctx)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	if err := b.compare(want, actual); err != nil {
		return firewall.AppliedState{}, err
	}
	b.known = cloneDecisions(live)
	b.knownValid = true
	return firewall.AppliedState{ObservedAt: b.options.Now(), Decisions: cloneDecisions(live), Simulated: false}, nil
}
func (b *Backend) apply(ctx context.Context, want map[string]map[string]bool, current observed) error {
	// Install scoped rules before adding entries; there is never a moment with
	// a source-only global drop rule. Remove empty rules only after entry cleanup.
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		rule := RichRule(b.options.Zone, b.options.Audience, binding)
		if len(want[name]) > 0 && !current.rules[rule] {
			if err := b.bus.AddRichRule(ctx, b.options.Zone, rule); err != nil {
				return fmt.Errorf("install owned rule: %w", err)
			}
		}
	}
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		existing := current.entries[name]
		remove := make([]string, 0)
		add := make([]string, 0)
		for ip := range existing {
			if !want[name][ip] {
				remove = append(remove, ip)
			}
		}
		for ip := range want[name] {
			if !existing[ip] {
				add = append(add, ip)
			}
		}
		sort.Strings(remove)
		sort.Strings(add)
		for _, ip := range remove {
			if err := b.bus.RemoveEntry(ctx, name, ip); err != nil {
				return fmt.Errorf("remove entry: %w", err)
			}
		}
		for _, ip := range add {
			if err := b.bus.AddEntry(ctx, name, ip); err != nil {
				return fmt.Errorf("add entry: %w", err)
			}
		}
	}
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		rule := RichRule(b.options.Zone, b.options.Audience, binding)
		if len(want[name]) == 0 && current.rules[rule] {
			if err := b.bus.RemoveRichRule(ctx, b.options.Zone, rule); err != nil {
				return fmt.Errorf("remove owned rule: %w", err)
			}
		}
	}
	return nil
}
func (b *Backend) compare(want map[string]map[string]bool, actual observed) error {
	for _, binding := range b.options.Bindings {
		name := SetName(b.options.Zone, b.options.Audience, binding)
		if len(want[name]) != len(actual.entries[name]) {
			return ErrDrift
		}
		for ip := range want[name] {
			if !actual.entries[name][ip] {
				return ErrDrift
			}
		}
		rule := RichRule(b.options.Zone, b.options.Audience, binding)
		if actual.rules[rule] != (len(want[name]) > 0) {
			return ErrDrift
		}
	}
	return nil
}

// Inspect reads D-Bus again; it never reports merely cached desired state.
// A new process with unknown nonempty sets will report drift, not invented
// decision IDs/TTLs. Only a successful Reconcile establishes provenance.
func (b *Backend) Inspect(ctx context.Context) (firewall.AppliedState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.probe(ctx); err != nil {
		return firewall.AppliedState{}, err
	}
	actual, err := b.observe(ctx)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	if !b.knownValid {
		for _, binding := range b.options.Bindings {
			name := SetName(b.options.Zone, b.options.Audience, binding)
			if len(actual.entries[name]) > 0 || actual.rules[RichRule(b.options.Zone, b.options.Audience, binding)] {
				return firewall.AppliedState{}, ErrDrift
			}
		}
		return firewall.AppliedState{ObservedAt: b.options.Now(), Simulated: false}, nil
	}
	// If the agent failed to reconcile before an expiry, this cannot be called
	// applied. The reconciler in issue #9 must remove entries promptly.
	for _, d := range b.known {
		if !d.ExpiresAt.After(b.options.Now()) {
			return firewall.AppliedState{}, ErrDrift
		}
	}
	want, err := b.desiredEntries(b.known)
	if err != nil {
		return firewall.AppliedState{}, err
	}
	if err := b.compare(want, actual); err != nil {
		return firewall.AppliedState{}, err
	}
	return firewall.AppliedState{ObservedAt: b.options.Now(), Decisions: cloneDecisions(b.known), Simulated: false}, nil
}

// RemoveOwned is independent of central controller reachability and local
// mode; it removes only the exact fingerprinted Fleetguard sets' runtime
// entries and their generated runtime rules. It never deletes the sets,
// reloads firewalld, or touches foreign rules/permanent configuration.
func (b *Backend) RemoveOwned(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.probe(ctx); err != nil {
		return err
	}
	want := make(map[string]map[string]bool, len(b.options.Bindings))
	for _, binding := range b.options.Bindings {
		want[SetName(b.options.Zone, b.options.Audience, binding)] = make(map[string]bool)
	}
	current, err := b.observe(ctx)
	if err != nil {
		return err
	}
	if err := b.apply(ctx, want, current); err != nil {
		return err
	}
	actual, err := b.observe(ctx)
	if err != nil {
		return err
	}
	if err := b.compare(want, actual); err != nil {
		return err
	}
	b.known = nil
	b.knownValid = true
	return nil
}
func cloneDecisions(in []protocol.Decision) []protocol.Decision {
	out := make([]protocol.Decision, len(in))
	copy(out, in)
	for i := range out {
		out[i].DestinationPorts = append([]uint16(nil), out[i].DestinationPorts...)
	}
	return out
}
