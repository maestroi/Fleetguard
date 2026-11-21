package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var reasonIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validID(s string) bool { return identifier.MatchString(s) }

// decodeJSON rejects unknown keys, extra JSON values, and overlarge messages.
func decodeJSON(data []byte, limit int, dst any) error {
	if len(data) > limit {
		return fail(ReasonOversized, "JSON exceeds %d bytes", limit)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fail(ReasonMalformed, "invalid JSON: %v", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fail(ReasonMalformed, "extra JSON value")
		}
		return fail(ReasonMalformed, "trailing JSON: %v", err)
	}
	return nil
}

func validatePorts(ports []uint16, max int) bool {
	if len(ports) == 0 || len(ports) > max {
		return false
	}
	prev := uint16(0)
	for _, p := range ports {
		if p <= prev {
			return false
		} // nonzero, unique, ordered
		prev = p
	}
	return true
}

// rejectDuplicateKeys walks a bounded JSON message without accepting ambiguous
// duplicate object members, including nested members. The depth bound also
// prevents excessively nested but size-limited inputs from consuming stack.
func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fail(ReasonMalformed, "JSON nesting too deep")
		}
		t, err := d.Token()
		if err != nil {
			return fail(ReasonMalformed, "invalid JSON token: %v", err)
		}
		switch t {
		case json.Delim('{'):
			seen := make(map[string]bool)
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return fail(ReasonMalformed, "invalid object key: %v", err)
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fail(ReasonMalformed, "duplicate JSON object member")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return fail(ReasonMalformed, "invalid object end")
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return fail(ReasonMalformed, "invalid array end")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	// The main decoder checks unknown fields and trailing values.
	return nil
}

// DecodeEvidence validates structure, freshness and authenticated node binding.
// Callers MUST get authenticatedNode from transport credentials, never the body.
func DecodeEvidence(data []byte, authenticatedNode string, now time.Time) (Evidence, error) {
	var e Evidence
	if err := decodeJSON(data, MaxEventBytes, &e); err != nil {
		return e, err
	}
	if err := ValidateEvidence(e, authenticatedNode, now); err != nil {
		return Evidence{}, err
	}
	return e, nil
}

func ValidateEvidence(e Evidence, authenticatedNode string, now time.Time) error {
	if e.Schema != SchemaVersion {
		return fail(ReasonInvalidSchema, "unsupported evidence schema")
	}
	if !validID(authenticatedNode) || !validID(e.NodeID) || e.NodeID != authenticatedNode {
		return fail(ReasonScopeMismatch, "node identity not authenticated or mismatched")
	}
	if !validID(e.EventID) || !validID(e.DedupKey) || !validID(e.Service) || !validID(e.Observation) {
		return fail(ReasonInvalidEvidence, "invalid identifier")
	}
	ip, err := netip.ParseAddr(e.SourceIP)
	if err != nil || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != e.SourceIP {
		return fail(ReasonInvalidEvidence, "invalid canonical source IP")
	}
	if e.Transport != TransportTCP && e.Transport != TransportUDP {
		return fail(ReasonInvalidEvidence, "unsupported transport")
	}
	if !validatePorts(e.DestinationPorts, MaxPortsPerEvent) {
		return fail(ReasonInvalidEvidence, "ports must be sorted, nonzero and unique")
	}
	if e.Attempts <= 0 || e.Attempts > MaxEventAttempts {
		return fail(ReasonInvalidEvidence, "attempt count out of bounds")
	}
	if e.WindowSeconds <= 0 || time.Duration(e.WindowSeconds)*time.Second > MaxEventWindow {
		return fail(ReasonInvalidEvidence, "window out of bounds")
	}
	if e.ProofLevel != ProofUnverifiedLog && e.ProofLevel != ProofEstablishedConnection && e.ProofLevel != ProofApplicationVerified {
		return fail(ReasonInvalidEvidence, "unsupported proof level")
	}
	if e.Transport == TransportUDP && e.ProofLevel == ProofEstablishedConnection {
		return fail(ReasonInvalidEvidence, "UDP cannot claim TCP established-connection proof")
	}
	if e.ObservedAt.IsZero() || e.ObservedAt.After(now.Add(MaxClockSkew)) || now.Sub(e.ObservedAt) > MaxEventAge {
		return fail(ReasonExpired, "evidence outside freshness window")
	}
	return nil
}

// ValidateSnapshot enforces structural limits, independent of current time.
// Additional local protection checks must run before *any* enforcement.
func ValidateSnapshot(s Snapshot) error {
	if s.Schema != SchemaVersion {
		return fail(ReasonInvalidSchema, "unsupported snapshot schema")
	}
	if s.Revision == 0 || !validID(s.KeyID) || !validID(s.Audience.ServiceGroup) || (s.Audience.NodeID != "" && !validID(s.Audience.NodeID)) {
		return fail(ReasonInvalidDecision, "missing revision, key ID or audience")
	}
	if s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > MaxSnapshotTTL {
		return fail(ReasonInvalidDecision, "snapshot lifetime out of bounds")
	}
	if s.Decisions == nil || len(s.Decisions) > MaxDecisions {
		return fail(ReasonInvalidDecision, "decisions missing or too numerous")
	}
	seen := make(map[string]struct{}, len(s.Decisions))
	for _, d := range s.Decisions {
		if !validID(d.ID) || !validID(d.Service) || !reasonIdentifier.MatchString(d.ReasonCode) {
			return fail(ReasonInvalidDecision, "decision identifiers or reason invalid")
		}
		if _, exists := seen[d.ID]; exists {
			return fail(ReasonInvalidDecision, "duplicate decision ID")
		}
		seen[d.ID] = struct{}{}
		if d.Action != ActionDrop || (d.Transport != TransportTCP && d.Transport != TransportUDP) || !validatePorts(d.DestinationPorts, MaxPortsPerDecision) {
			return fail(ReasonInvalidDecision, "unsupported action, transport, or ports")
		}
		source, err := netip.ParsePrefix(d.Source)
		if err != nil || !source.IsValid() || !source.Addr().Is4() || source.Bits() != 32 || source.Masked() != source || source.Addr().IsUnspecified() || source.Addr().IsMulticast() || source.String() != d.Source {
			return fail(ReasonInvalidDecision, "only canonical IPv4 /32 host sources are supported")
		}
		if !d.ExpiresAt.After(s.IssuedAt) || d.ExpiresAt.After(s.ExpiresAt) {
			return fail(ReasonInvalidDecision, "decision expiry outside snapshot lifetime")
		}
	}
	return nil
}

// ParseSnapshot provides a strict decoder for *unsigned* fixture/authoring data.
// Never treat its result as authenticated; VerifySignedSnapshot is required.
func ParseSnapshot(data []byte) (Snapshot, error) {
	var s Snapshot
	if err := decodeJSON(data, MaxSnapshotBytes, &s); err != nil {
		return Snapshot{}, err
	}
	if err := ValidateSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

func ValidateAcknowledgement(a Acknowledgement) error {
	if a.Schema != SchemaVersion || !validID(a.NodeID) || a.Revision == 0 {
		return fail(ReasonInvalidSchema, "invalid ack schema, node or revision")
	}
	if !slices.Contains([]DecisionState{StateReceived, StateValidated, StateApplied, StateRejected, StateError}, a.State) {
		return fail(ReasonInvalidDecision, "unknown acknowledgement state")
	}
	if a.State == StateRejected || a.State == StateError {
		if !slices.Contains([]ReasonCode{ReasonMalformed, ReasonOversized, ReasonInvalidSchema, ReasonInvalidEvidence, ReasonInvalidDecision, ReasonUnknownSigner, ReasonInvalidSignature, ReasonNotCanonical, ReasonExpired, ReasonClockSkew, ReasonReplay, ReasonScopeMismatch}, a.Reason) {
			return fail(ReasonInvalidDecision, "rejected or error acknowledgement needs valid reason")
		}
	} else if a.Reason != "" {
		return fail(ReasonInvalidDecision, "success acknowledgement cannot include rejection reason")
	}
	return nil
}

// Reason returns a stable machine-readable code for protocol errors.
func Reason(err error) ReasonCode {
	var p *ProtocolError
	if errors.As(err, &p) {
		return p.Code
	}
	return ReasonMalformed
}
