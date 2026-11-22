package exposure

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// Observed is explicitly a snapshot of what the observer could inspect.
// Missing coverage is unknown, not evidence of a closed firewall or internet
// unreachability. Only controlled external probes can assert reachability.
type Coverage struct {
	Listeners  bool     `json:"listeners"`
	Firewalld  bool     `json:"firewalld"`
	Forwarding bool     `json:"forwarding"`
	External   bool     `json:"external"`
	Notes      []string `json:"notes,omitempty"`
}
type Listener struct {
	Transport protocol.Transport `json:"transport"`
	Port      uint16             `json:"port"`
	Bind      string             `json:"bind"` // wildcard, loopback or interface
}
type Path struct {
	Direction  string             `json:"direction"`
	Transport  protocol.Transport `json:"transport"`
	Port       uint16             `json:"port"`
	Source     string             `json:"source"`
	Zone       string             `json:"zone,omitempty"`
	Interface  string             `json:"interface,omitempty"`
	State      string             `json:"state"`      // configured_allow, verified_reachable, verified_blocked
	Provenance string             `json:"provenance"` // firewall_runtime, container_publish, external_probe
}
type Observed struct {
	Schema     int        `json:"schema"`
	ObservedAt time.Time  `json:"observed_at"`
	Coverage   Coverage   `json:"coverage"`
	Listeners  []Listener `json:"listeners"`
	Paths      []Path     `json:"paths"`
}

func (o Observed) Validate() error {
	if o.Schema != SchemaVersion || o.ObservedAt.IsZero() || len(o.Listeners) > 8192 || len(o.Paths) > 8192 || len(o.Coverage.Notes) > 32 {
		return errors.New("exposure: invalid observed schema, time or cardinality")
	}
	for _, s := range o.Listeners {
		if (s.Transport != protocol.TransportTCP && s.Transport != protocol.TransportUDP) || s.Port == 0 || (s.Bind != "wildcard" && s.Bind != "loopback" && s.Bind != "interface") {
			return fmt.Errorf("exposure: invalid observed listener %+v", s)
		}
	}
	for _, p := range o.Paths {
		if p.Direction != "ingress" && p.Direction != "egress" || (p.Transport != protocol.TransportTCP && p.Transport != protocol.TransportUDP) ||
			p.Port == 0 || !validSource(p.Source) || p.Zone != "" && !identifier.MatchString(p.Zone) || p.Interface != "" && !identifier.MatchString(p.Interface) {
			return fmt.Errorf("exposure: invalid observed path %+v", p)
		}
		switch p.Provenance {
		case "external_probe":
			if (p.State != "verified_reachable" && p.State != "verified_blocked") || !o.Coverage.External {
				return errors.New("exposure: external probe requires explicitly declared external coverage")
			}
		case "firewall_runtime":
			if p.State != "configured_allow" || !o.Coverage.Firewalld {
				return errors.New("exposure: invalid firewall evidence or coverage")
			}
		case "container_publish":
			if p.State != "configured_allow" || !o.Coverage.Forwarding {
				return errors.New("exposure: invalid container publication evidence or coverage")
			}
		default:
			return fmt.Errorf("exposure: unsupported path provenance %q", p.Provenance)
		}
	}
	return nil
}

type Finding struct {
	ID         string             `json:"id"`
	Code       string             `json:"code"`
	Severity   string             `json:"severity"`
	Confidence string             `json:"confidence"` // verified_external, configured_only, local_only, unknown
	Transport  protocol.Transport `json:"transport"`
	Port       uint16             `json:"port"`
	Source     string             `json:"source"`
	Expected   string             `json:"expected,omitempty"`
	Profile    string             `json:"profile,omitempty"`
	Detail     string             `json:"detail"`
}
type Report struct {
	Schema         int        `json:"schema"`
	NodeID         string     `json:"node_id"`
	Role           string     `json:"role"`
	ObservedAt     time.Time  `json:"last_observed_at"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
	ProfileVersion int        `json:"profile_version"`
	Coverage       Coverage   `json:"coverage"`
	Findings       []Finding  `json:"findings"`
	Truncated      bool       `json:"truncated,omitempty"`
}

func covers(rule Rule, path Path) bool {
	if rule.Direction != path.Direction || rule.Transport != path.Transport || !rule.Ports.Contains(path.Port) {
		return false
	}
	if rule.Zone != "" && rule.Zone != path.Zone || rule.Interface != "" && rule.Interface != path.Interface {
		return false
	}
	if rule.Source == path.Source || rule.Source == "any" {
		return true
	}
	// A configured broad source never inherits authorization intended for a
	// narrower CIDR. A CIDR is only allowed by an exact CIDR, containing range
	// or the explicit 'any' source selector.
	if len(rule.Source) > 5 && rule.Source[:5] == "cidr:" && len(path.Source) > 5 && path.Source[:5] == "cidr:" {
		return sourceContains(rule.Source, path.Source)
	}
	return false
}
func sourceContains(want, observed string) bool {
	a := want[5:]
	b := observed[5:]
	pa, errA := parsePrefix(a)
	pb, errB := parsePrefix(b)
	return errA == nil && errB == nil && pa.Bits() <= pb.Bits() && pa.Contains(pb.Addr())
}
func parsePrefix(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }
func applicable(r Rule, p Path) bool {
	return covers(r, p) || (r.Intent == "forbidden" && r.Direction == p.Direction && r.Transport == p.Transport &&
		r.Ports.Contains(p.Port) && (r.Zone == "" || r.Zone == p.Zone) && (r.Interface == "" || r.Interface == p.Interface) && sourceOverlap(r.Source, p.Source))
}
func intentFor(rules []Rule, p Path) (intent string, profile string) {
	for _, r := range rules {
		if !applicable(r, p) {
			continue
		}
		if r.Intent == "forbidden" {
			return r.Intent, r.Profile + "/" + r.ID
		}
		if covers(r, p) {
			if r.Intent == "required" {
				return r.Intent, r.Profile + "/" + r.ID
			}
			intent = r.Intent
			profile = r.Profile + "/" + r.ID
		}
	}
	return intent, profile
}
func finding(code, severity, confidence string, p Path, expected, profile, detail string) Finding {
	idKey := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s", code, p.Direction, p.Transport, p.Port, p.Source, p.Zone, p.Interface)
	hash := sha256.Sum256([]byte(idKey))
	return Finding{ID: hex.EncodeToString(hash[:8]), Code: code, Severity: severity, Confidence: confidence,
		Transport: p.Transport, Port: p.Port, Source: p.Source, Expected: expected, Profile: profile, Detail: detail}
}

// Evaluate produces configuration drift, NOT a firewall command or an attacker
// reputation score. Listener-only observations never assert public reachability.
func Evaluate(expected Effective, observed Observed) (Report, error) {
	if err := observed.Validate(); err != nil {
		return Report{}, err
	}
	report := Report{Schema: SchemaVersion, NodeID: expected.NodeID, Role: expected.Role, ObservedAt: observed.ObservedAt,
		ProfileVersion: SchemaVersion, Coverage: observed.Coverage, Findings: make([]Finding, 0)}
	if observed.Coverage.External {
        for _, path := range observed.Paths {
            if path.Provenance == "external_probe" {
                at := observed.ObservedAt
                report.LastVerifiedAt = &at
                break
            }
        }
    }
	add := func(f Finding) {
		if len(report.Findings) < 256 {
			report.Findings = append(report.Findings, f)
		} else {
			report.Truncated = true
		}
	}
	seen := map[string]bool{}
	// Path evidence is only 'configured' unless independently probed. Firewalld
	// zones, DNS, provider NAT, Docker forwarding and host listeners alone do
	// not establish end-to-end reachability.
	for _, p := range observed.Paths {
		intent, profile := intentFor(expected.Rules, p)
		if p.State == "verified_blocked" {
			continue
		}
		verified := p.Provenance == "external_probe" && p.State == "verified_reachable"
		confidence := "configured_only"
		if verified {
			confidence = "verified_external"
		}
		var f Finding
		switch {
		case intent == "forbidden":
			f = finding("forbidden_exposure", "critical", confidence, p, intent, profile, "Forbidden "+p.Direction+" path observed; verify packet path and locally protected access")
		case intent == "" && (p.Source == "public" || p.Source == "any"):
			f = finding("unexpected_public_exposure", "high", confidence, p, "", profile, "Public-facing path is not authorized by this node role; configured access is not proof of external reachability")
		default:
			continue
		}
		if !seen[f.ID] {
			seen[f.ID] = true
			add(f)
		}
	}
	// Listeners on wildcard/interface addresses are visible local attack surface,
	// not verified internet routes. Report unclassified listeners distinctly,
	// even where firewalld/forwarding visibility is incomplete.
	for _, s := range observed.Listeners {
		if s.Bind == "loopback" {
			continue
		}
		p := Path{Direction: "ingress", Transport: s.Transport, Port: s.Port, Source: "public"}
		intent, _ := intentFor(expected.Rules, p)
		if intent == "" {
			f := finding("unexpected_listener", "medium", "local_only", p, "", "", "Listening socket not covered by assigned role; reachability unknown")
			if !seen[f.ID] {
				seen[f.ID] = true
				add(f)
			}
		}
	}
	// Required ranges express an obligation. A missing host listener is
	// conclusive only if local listeners AND container forwarding inventory are
	// complete. Never claim that an open listener itself is reachable.
	for _, r := range expected.Rules {
		if r.Intent != "required" || r.Direction != "ingress" {
			continue
		}
		ready := false
		blocked := false
		for _, p := range observed.Paths {
			if !covers(r, p) {
				continue
			}
			if p.State == "verified_reachable" {
				ready = true
				break
			}
			if p.State == "verified_blocked" {
				blocked = true
			}
			if p.State == "configured_allow" {
				ready = true
			} // configured, not verified
		}
		if !ready {
			for _, s := range observed.Listeners {
				if s.Transport == r.Transport && r.Ports.Contains(s.Port) && s.Bind != "loopback" {
					ready = true
					break
				}
			}
		}
		if ready && !blocked {
			continue
		}
		path := Path{Direction: r.Direction, Transport: r.Transport, Port: r.Ports.From, Source: r.Source, Zone: r.Zone, Interface: r.Interface}
		switch {
		case blocked:
			f := finding("required_port_unavailable", "high", "verified_external", path, r.Intent, r.Profile+"/"+r.ID, "Controlled external probe reports required ingress unavailable")
			if !seen[f.ID] {
				seen[f.ID] = true
				add(f)
			}
		case observed.Coverage.Listeners && observed.Coverage.Forwarding:
			f := finding("required_port_unavailable", "high", "local_only", path, r.Intent, r.Profile+"/"+r.ID, "No matching host listener or published container port observed; external reachability not measured")
			if !seen[f.ID] {
				seen[f.ID] = true
				add(f)
			}
		default:
			f := finding("unknown_path", "medium", "unknown", path, r.Intent, r.Profile+"/"+r.ID, "Incomplete host/forwarding coverage prevents determining required ingress state")
			if !seen[f.ID] {
				seen[f.ID] = true
				add(f)
			}
		}
	}
	// Every exposed listener with missing firewall or forwarding coverage is a
	// visibility gap, not positive evidence of internet exposure.
	if !observed.Coverage.Firewalld || !observed.Coverage.Forwarding {
		for _, s := range observed.Listeners {
			if s.Bind == "loopback" {
				continue
			}
			p := Path{Direction: "ingress", Transport: s.Transport, Port: s.Port, Source: "public"}
			f := finding("unknown_path", "low", "unknown", p, "", "", "Firewall or forwarding visibility incomplete; listener does not prove internet reachability")
			if !seen[f.ID] {
				seen[f.ID] = true
				add(f)
			}
		}
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Transport != b.Transport {
			return a.Transport < b.Transport
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.ID < b.ID
	})
	report.Findings = slices.Clip(report.Findings)
	return report, nil
}

// ParseObserved only accepts a bounded, strictly typed observation fixture.
// Live observers must never accept remote values as permission to alter rules.
func ParseObserved(data []byte, out *Observed) error {
	if out == nil {
		return errors.New("exposure: nil observation destination")
	}
	if err := strict(data, 512<<10, out); err != nil {
		return err
	}
	return out.Validate()
}
