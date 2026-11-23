// Package correlation evaluates authenticated, bounded, service-scoped evidence
// into observe-only policy candidates. It never signs or applies decisions.
package correlation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const MaxPolicyBytes = 32 << 10
const MaxEvidence = 4096
const MaxCandidates = 64

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Scope struct {
	Service     string             `json:"service"`
	Observation string             `json:"observation"`
	Transport   protocol.Transport `json:"transport"`
	Port        uint16             `json:"port"`
}

// Config is installed locally by an operator and NEVER accepted over HTTPS.
// Each node must have an explicit independence domain; two identities in the
// same domain do not count as independent evidence.
type Config struct {
	Schema             int               `json:"schema"`
	Mode               string            `json:"mode"`
	Group              string            `json:"group"`
	WindowSeconds      int               `json:"window_seconds"`
	DecisionTTLSeconds int               `json:"decision_ttl_seconds"`
	MinNodes           int               `json:"min_nodes"`
	MinDomains         int               `json:"min_domains"`
	MaxEvidence        int               `json:"max_evidence"`
	MaxCandidates      int               `json:"max_candidates"`
	NodeDomains        map[string]string `json:"node_domains"`
	Scopes             []Scope           `json:"scopes"`
	ProtectedSources   []string          `json:"protected_sources"`
	SharedNATSources   []string          `json:"shared_nat_sources"`
}

type compiled struct {
	cfg       Config
	scopes    map[string]bool
	protected []netip.Prefix
	shared    []netip.Prefix
}

func scopeKey(service, observation string, transport protocol.Transport, port uint16) string {
	return fmt.Sprintf("%s/%s/%s/%d", service, observation, transport, port)
}
func (c Config) validate() (compiled, error) {
	x := compiled{cfg: c, scopes: make(map[string]bool)}
	if c.Schema != 1 || c.Mode != "observe" || !identifier.MatchString(c.Group) {
		return x, errors.New("correlation must be schema 1, observe mode and have a valid group")
	}
	if c.WindowSeconds < 10 || c.WindowSeconds > 300 || c.DecisionTTLSeconds < 5 || c.DecisionTTLSeconds > 120 || c.MinNodes < 2 || c.MinNodes > 256 || c.MinDomains < 2 || c.MinDomains > c.MinNodes || c.MaxEvidence < 1 || c.MaxEvidence > MaxEvidence || c.MaxCandidates < 1 || c.MaxCandidates > MaxCandidates {
		return x, errors.New("invalid correlation thresholds, TTL, window, or capacity")
	}
	if len(c.Scopes) == 0 || len(c.Scopes) > 128 || len(c.NodeDomains) < c.MinNodes || len(c.NodeDomains) > 256 {
		return x, errors.New("explicit scopes and enough node domains required")
	}
	distinctDomains := map[string]bool{}
	for node, domain := range c.NodeDomains {
		if !identifier.MatchString(node) || !identifier.MatchString(domain) {
			return x, errors.New("invalid domain assignment")
		}
		distinctDomains[domain] = true
	}
	if len(distinctDomains) < c.MinDomains {
		return x, errors.New("not enough independent trust domains")
	}
	for _, s := range c.Scopes {
		if !identifier.MatchString(s.Service) || !identifier.MatchString(s.Observation) || (s.Transport != protocol.TransportTCP && s.Transport != protocol.TransportUDP) || s.Port == 0 {
			return x, errors.New("invalid service/protocol/port scope")
		}
		k := scopeKey(s.Service, s.Observation, s.Transport, s.Port)
		if x.scopes[k] {
			return x, errors.New("duplicate scope")
		}
		x.scopes[k] = true
	}
	parsePrefixes := func(raw []string) ([]netip.Prefix, error) {
		if len(raw) > 256 {
			return nil, errors.New("too many protected/shared prefixes")
		}
		out := make([]netip.Prefix, 0, len(raw))
		seen := map[string]bool{}
		for _, r := range raw {
			p, err := netip.ParsePrefix(r)
			if err != nil || !p.IsValid() || p.Masked() != p || p.String() != r || seen[r] {
				return nil, errors.New("invalid, noncanonical or duplicate network prefix")
			}
			seen[r] = true
			out = append(out, p)
		}
		return out, nil
	}
	var err error
	x.protected, err = parsePrefixes(c.ProtectedSources)
	if err != nil {
		return x, err
	}
	x.shared, err = parsePrefixes(c.SharedNATSources)
	if err != nil {
		return x, err
	}
	return x, nil
}

// Load validates a private local policy; it has no network-loading variant.
func Load(path string) (Config, error) {
	var c Config
	if err := auth.PrivateFile(path); err != nil {
		return c, err
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return c, err
	}
	if len(b) > MaxPolicyBytes {
		return c, errors.New("correlation policy too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return Config{}, err
	}
	var rest any
	if err = d.Decode(&rest); err != io.EOF {
		return Config{}, errors.New("trailing correlation config JSON")
	}
	if _, err = c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Candidate is a *proposed* scoped action, not a remotely executable rule.
// A shared-NAT source is flagged for manual review and gets no Decision.
type Candidate struct {
	Source         string              `json:"source"`
	Service        string              `json:"service"`
	Observation    string              `json:"observation"`
	Transport      protocol.Transport  `json:"transport"`
	Port           uint16              `json:"port"`
	ProofLevel     protocol.ProofLevel `json:"proof_level"`
	Nodes          []string            `json:"nodes"`
	Domains        []string            `json:"domains"`
	AttemptsCapped int                 `json:"attempts_capped"`
	Status         string              `json:"status"`
	ReasonCode     string              `json:"reason_code"`
	Decision       *protocol.Decision  `json:"decision,omitempty"`
}

type Report struct {
	Mode               string      `json:"mode"`
	Group              string      `json:"group"`
	EvaluatedAt        time.Time   `json:"evaluated_at"`
	EvidenceRead       int         `json:"evidence_read"`
	EvidenceRejected   int         `json:"evidence_rejected"`
	WeakEvidence       int         `json:"weak_evidence"`
	SourcesSuppressed  int         `json:"sources_suppressed"`
	Candidates         []Candidate `json:"candidates"`
	RealFirewallWrites int         `json:"real_firewall_writes"`
	PublishedPolicies  int         `json:"published_policies"`
}

type vote struct {
	node     string
	domain   string
	attempts int
}

// Evaluate is order-independent and uses only explicitly authorized nodes,
// group scopes and application-verified proof. The input must originate from a
// trusted store that bound node ID to authentication at ingestion.
func Evaluate(c Config, registry auth.Registry, evidence []protocol.Evidence, now time.Time) (Report, error) {
	return evaluate(c, registry, evidence, now, netip.Prefix{})
}

// EvaluateLab limits eligible sources to one explicitly selected private lab subnet.
func EvaluateLab(c Config, registry auth.Registry, evidence []protocol.Evidence, now time.Time, subnet netip.Prefix) (Report, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.Bits() < 24 || !subnet.Addr().IsPrivate() {
		return Report{}, errors.New("lab evaluation requires a canonical private IPv4 subnet of /24 or narrower")
	}
	return evaluate(c, registry, evidence, now, subnet)
}

func evaluate(c Config, registry auth.Registry, evidence []protocol.Evidence, now time.Time, subnet netip.Prefix) (Report, error) {
	x, err := c.validate()
	if err != nil {
		return Report{}, err
	}
	if len(evidence) > c.MaxEvidence {
		return Report{}, errors.New("evidence over capacity: refusing partial correlation")
	}
	now = now.UTC()
	out := Report{Mode: "observe_only", Group: c.Group, EvaluatedAt: now, EvidenceRead: len(evidence), Candidates: []Candidate{}}
	type key struct {
		ip, service, observation string
		transport                protocol.Transport
		port                     uint16
		proof                    protocol.ProofLevel
	}
	votes := map[key]map[string]vote{}
	seen := map[string]bool{}
	suppressed := map[string]bool{}
	for _, e := range evidence {
		if err := protocol.ValidateEvidence(e, e.NodeID, now); err != nil || e.ObservedAt.After(now) || now.Sub(e.ObservedAt) > time.Duration(c.WindowSeconds)*time.Second {
			out.EvidenceRejected++
			continue
		}
		dedup := e.NodeID + "\x00" + e.EventID + "\x00" + e.DedupKey
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		domain, allowed := c.NodeDomains[e.NodeID]
		if !allowed {
			out.EvidenceRejected++
			continue
		}
		var n auth.Node
		found := false
		for _, node := range registry.Nodes {
			if node.NodeID == e.NodeID && !node.Revoked {
				n = node
				found = true
				break
			}
		}
		if !found || !registry.CanAccess(n, c.Group, e.Service) {
			out.EvidenceRejected++
			continue
		}
		if e.ProofLevel != protocol.ProofApplicationVerified {
			out.WeakEvidence++
			continue
		}
		ip, err := netip.ParseAddr(e.SourceIP)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			out.EvidenceRejected++
			continue
		}
		if (subnet.IsValid() && !subnet.Contains(ip)) || (!subnet.IsValid() && ip.IsPrivate()) {
			out.EvidenceRejected++
			continue
		}
		blocked := false
		for _, p := range x.protected {
			if p.Contains(ip) {
				blocked = true
				break
			}
		}
		if blocked {
			suppressed[e.SourceIP] = true
			continue
		}
		for _, port := range e.DestinationPorts {
			if !x.scopes[scopeKey(e.Service, e.Observation, e.Transport, port)] {
				continue
			}
			k := key{ip: e.SourceIP, service: e.Service, observation: e.Observation, transport: e.Transport, port: port, proof: e.ProofLevel}
			if votes[k] == nil {
				votes[k] = map[string]vote{}
			}
			v := votes[k][e.NodeID]
			v.node = e.NodeID
			v.domain = domain
			// One per-node vote. Saturated attempts prevent a noisy reporter from
			// dominating the evaluation irrespective of event count or ordering.
			if v.attempts == 0 {
				v.attempts = min(e.Attempts, 100)
			} else {
				v.attempts = max(v.attempts, min(e.Attempts, 100))
			}
			votes[k][e.NodeID] = v
		}
	}
	out.SourcesSuppressed = len(suppressed)
	keys := make([]key, 0, len(votes))
	for k := range votes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return strings.Compare(fmt.Sprintf("%s/%s/%s/%s/%05d/%s", a.ip, a.service, a.observation, a.transport, a.port, a.proof), fmt.Sprintf("%s/%s/%s/%s/%05d/%s", b.ip, b.service, b.observation, b.transport, b.port, b.proof)) < 0
	})
	for _, k := range keys {
		byNode := votes[k]
		if len(byNode) < c.MinNodes {
			continue
		}
		domains := map[string]bool{}
		nodes := make([]string, 0, len(byNode))
		attempts := 0
		for id, v := range byNode {
			nodes = append(nodes, id)
			domains[v.domain] = true
			attempts += v.attempts
		}
		if len(domains) < c.MinDomains {
			continue
		}
		sort.Strings(nodes)
		distinct := make([]string, 0, len(domains))
		for d := range domains {
			distinct = append(distinct, d)
		}
		sort.Strings(distinct)
		cand := Candidate{Source: k.ip, Service: k.service, Transport: k.transport, Port: k.port, ProofLevel: k.proof, Nodes: nodes, Domains: distinct, AttemptsCapped: attempts, Status: "candidate", ReasonCode: "verified_multi_node_abuse"}
		ip := netip.MustParseAddr(k.ip)
		shared := false
		for _, p := range x.shared {
			if p.Contains(ip) {
				shared = true
				break
			}
		}
		if shared {
			cand.Status = "manual_review"
			cand.ReasonCode = "shared_nat_review"
		} else {
			idInput := fmt.Sprintf("v1/%s/%s/%s/%s/%s/%d", c.Group, k.ip, k.service, k.observation, k.transport, k.port)
			digest := sha256.Sum256([]byte(idInput))
			d := protocol.Decision{ID: "correlation-" + hex.EncodeToString(digest[:12]), Source: ip.String() + "/32", Action: protocol.ActionDrop, Service: k.service, Transport: k.transport, DestinationPorts: []uint16{k.port}, ExpiresAt: now.Add(time.Duration(c.DecisionTTLSeconds) * time.Second), ReasonCode: cand.ReasonCode}
			cand.Decision = &d
		}
		if len(out.Candidates) >= c.MaxCandidates {
			return Report{}, errors.New("candidate capacity exceeded: refusing partial correlation")
		}
		out.Candidates = append(out.Candidates, cand)
	}
	return out, nil
}

// Validate exposes preflight checks to offline/operator commands and tests.
func Validate(c Config) error { _, err := c.validate(); return err }

// TestPolicySource provides deterministic sorting for operator/audit output.
func CandidateSources(report Report) []string {
	v := make([]string, 0, len(report.Candidates))
	for _, c := range report.Candidates {
		v = append(v, c.Source)
	}
	slices.Sort(v)
	return v
}
