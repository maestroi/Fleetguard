// Package protocol defines versioned, data-only Fleetguard evidence and policy
// contracts. It is not a firewall implementation. Callers must authenticate
// network peers and apply local safety policy independently.
package protocol

import (
	"fmt"
	"time"
)

const (
	SchemaVersion       = 1
	MaxEventBytes       = 16 << 10
	MaxSnapshotBytes    = 128 << 10
	MaxEnvelopeBytes    = 180 << 10
	MaxDecisions        = 256
	MaxPortsPerDecision = 16
	MaxPortsPerEvent    = 32
	MaxSnapshotTTL      = 5 * time.Minute
	MaxEventAge         = 10 * time.Minute
	MaxClockSkew        = 30 * time.Second
	MaxEventWindow      = 5 * time.Minute
	MaxEventAttempts    = 1_000_000
)

type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Proof levels describe *claims*, not independently verified trust. The
// controller must bind the reporting node to authenticated transport identity
// and must not promote raw network logs to automatic fleet bans.
type ProofLevel string

const (
	ProofUnverifiedLog         ProofLevel = "unverified_network_log"
	ProofEstablishedConnection ProofLevel = "established_connection"
	ProofApplicationVerified   ProofLevel = "application_verified"
)

// Evidence is reported by an agent. NodeID is untrusted on its own: the server
// must compare it to its independently authenticated connection identity.
type Evidence struct {
	Schema           int        `json:"schema"`
	EventID          string     `json:"event_id"`
	NodeID           string     `json:"node_id"`
	DedupKey         string     `json:"dedup_key"`
	ObservedAt       time.Time  `json:"observed_at"`
	WindowSeconds    int        `json:"window_seconds"`
	SourceIP         string     `json:"source_ip"`
	Service          string     `json:"service"`
	Transport        Transport  `json:"transport"`
	DestinationPorts []uint16   `json:"destination_ports"`
	Observation      string     `json:"observation"`
	Attempts         int        `json:"attempts"`
	ProofLevel       ProofLevel `json:"proof_level"`
}

// Audience explicitly identifies a service group and optionally a single node.
// An absent NodeID means the snapshot is intended for *all* nodes that the
// server has independently authorized as members of ServiceGroup.
type Audience struct {
	ServiceGroup string `json:"service_group"`
	NodeID       string `json:"node_id,omitempty"`
}

type Action string

const ActionDrop Action = "drop"

// Decision is a scoped proposal, never a command. No command or shell field is
// permitted; unknown fields fail the canonical verification check.
type Decision struct {
	ID               string    `json:"id"`
	Source           string    `json:"source"` // canonical IPv4 host /32 only in v1
	Action           Action    `json:"action"`
	Service          string    `json:"service"`
	Transport        Transport `json:"transport"`
	DestinationPorts []uint16  `json:"destination_ports"`
	ExpiresAt        time.Time `json:"expires_at"`
	ReasonCode       string    `json:"reason_code"`
}

type Snapshot struct {
	Schema    int        `json:"schema"`
	Revision  uint64     `json:"revision"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Audience  Audience   `json:"audience"`
	Decisions []Decision `json:"decisions"`
	KeyID     string     `json:"key_id"`
}

// SignedSnapshot retains exact signed bytes in base64: never reconstruct a
// signature input by re-marshaling an untrusted JSON object.
type SignedSnapshot struct {
	PayloadBase64   string `json:"payload_b64"`
	SignatureBase64 string `json:"signature_b64"`
}

type DecisionState string

const (
	StateReceived  DecisionState = "received"
	StateValidated DecisionState = "validated"
	StateApplied   DecisionState = "applied"
	StateRejected  DecisionState = "rejected"
	StateError     DecisionState = "error"
)

type ReasonCode string

const (
	ReasonMalformed        ReasonCode = "malformed"
	ReasonOversized        ReasonCode = "oversized"
	ReasonInvalidSchema    ReasonCode = "invalid_schema"
	ReasonInvalidEvidence  ReasonCode = "invalid_evidence"
	ReasonInvalidDecision  ReasonCode = "invalid_decision"
	ReasonUnknownSigner    ReasonCode = "unknown_signer"
	ReasonInvalidSignature ReasonCode = "invalid_signature"
	ReasonNotCanonical     ReasonCode = "not_canonical"
	ReasonExpired          ReasonCode = "expired"
	ReasonClockSkew        ReasonCode = "clock_skew"
	ReasonReplay           ReasonCode = "replay"
	ReasonScopeMismatch    ReasonCode = "scope_mismatch"
)

type Acknowledgement struct {
	Schema   int           `json:"schema"`
	NodeID   string        `json:"node_id"`
	Revision uint64        `json:"revision"`
	State    DecisionState `json:"state"`
	Reason   ReasonCode    `json:"reason,omitempty"`
}

type ProtocolError struct {
	Code   ReasonCode
	Detail string
}

func (e *ProtocolError) Error() string { return fmt.Sprintf("protocol %s: %s", e.Code, e.Detail) }
func fail(code ReasonCode, format string, args ...any) error {
	return &ProtocolError{Code: code, Detail: fmt.Sprintf(format, args...)}
}
