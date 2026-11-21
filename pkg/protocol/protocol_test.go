package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
var expectedAudience = Audience{ServiceGroup: "public-rpc", NodeID: "lab-node-a"}

func testKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("Fleetguard deterministic testing key - NEVER use for deployment"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func signedFixture(t *testing.T) SignedSnapshot {
	t.Helper()
	e, err := DecodeSignedSnapshot(fixture(t, "snapshot_signed_valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{"lab-key-1": testKey().Public().(ed25519.PublicKey)}
}
func verify(envelope SignedSnapshot, now time.Time, revision uint64, audience Audience, known map[string]ed25519.PublicKey) (Snapshot, error) {
	return VerifySignedSnapshot(envelope, known, audience, revision, now)
}
func assertCode(t *testing.T, err error, code ReasonCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected code %q, got success", code)
	}
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != code {
		t.Fatalf("expected %q, got %v", code, err)
	}
}

func TestSignedFixtureAndCanonicalRoundTrip(t *testing.T) {
	s, err := ParseSnapshot(fixture(t, "snapshot_unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := SignSnapshot(s, testKey())
	if err != nil {
		t.Fatal(err)
	}
	want := signedFixture(t)
	if generated != want {
		t.Fatal("signed fixture changed; protocol encoding is not deterministic")
	}
	raw, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verify(decoded, fixedNow, 6, expectedAudience, keys())
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 7 || len(result.Decisions) != 1 || result.Decisions[0].Source != "203.0.113.42/32" {
		t.Fatal("unexpected verified snapshot")
	}
	// Group snapshots are valid for nodes in that group, but a node-targeted
	// snapshot is not valid for a different node in the same group.
	s.Audience.NodeID = ""
	group, err := SignSnapshot(s, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(group, fixedNow, 6, Audience{ServiceGroup: "public-rpc", NodeID: "lab-node-b"}, keys()); err != nil {
		t.Fatal(err)
	}
}

func TestSigningAndWireFailures(t *testing.T) {
	s, err := ParseSnapshot(fixture(t, "snapshot_unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignSnapshot(s, ed25519.PrivateKey("short"))
	assertCode(t, err, ReasonInvalidSignature)
	_, err = DecodeSignedSnapshot(fixture(t, "snapshot_malformed.json"))
	assertCode(t, err, ReasonMalformed)
	for _, wire := range []string{
		`{"payload_b64":"abc","payload_b64":"abc","signature_b64":"bad"}`,
		`{"payload_b64":"abc","signature_b64":"bad","shell":"rm -rf /"}`,
		`{"payload_b64":"abc"}`,
		`{"payload_b64":"abc","signature_b64":"bad"} {}`,
		`null`,
	} {
		if _, err := DecodeSignedSnapshot([]byte(wire)); err == nil {
			t.Errorf("accepted malformed envelope: %s", wire)
		}
	}
	_, err = DecodeSignedSnapshot(bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1))
	assertCode(t, err, ReasonOversized)
}

func TestVerificationRejections(t *testing.T) {
	valid := signedFixture(t)
	tests := []struct {
		name     string
		envelope SignedSnapshot
		now      time.Time
		revision uint64
		audience Audience
		keys     map[string]ed25519.PublicKey
		want     ReasonCode
	}{
		{"expired", valid, fixedNow.Add(3 * time.Minute), 6, expectedAudience, keys(), ReasonExpired},
		{"replay", valid, fixedNow, 7, expectedAudience, keys(), ReasonReplay},
		{"stale_revision", valid, fixedNow, 8, expectedAudience, keys(), ReasonReplay},
		{"wrong_node", valid, fixedNow, 6, Audience{NodeID: "lab-node-b", ServiceGroup: "public-rpc"}, keys(), ReasonScopeMismatch},
		{"wrong_group", valid, fixedNow, 6, Audience{NodeID: "lab-node-a", ServiceGroup: "ssh"}, keys(), ReasonScopeMismatch},
		{"future_issued", valid, fixedNow.Add(-time.Minute), 6, expectedAudience, keys(), ReasonClockSkew},
		{"unknown_signer", valid, fixedNow, 6, expectedAudience, map[string]ed25519.PublicKey{}, ReasonUnknownSigner},
		{"invalid_trust_key", valid, fixedNow, 6, expectedAudience, map[string]ed25519.PublicKey{"lab-key-1": {}}, ReasonUnknownSigner},
		{"missing_expected_node", valid, fixedNow, 6, Audience{ServiceGroup: "public-rpc"}, keys(), ReasonScopeMismatch},
		{"oversized_base64", SignedSnapshot{PayloadBase64: strings.Repeat("A", base64Codec.EncodedLen(MaxSnapshotBytes)+1), SignatureBase64: valid.SignatureBase64}, fixedNow, 6, expectedAudience, keys(), ReasonOversized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(tc.envelope, tc.now, tc.revision, tc.audience, tc.keys)
			assertCode(t, err, tc.want)
		})
	}
}

func TestEverySignedByteIsAuthenticated(t *testing.T) {
	valid := signedFixture(t)
	raw, err := base64Codec.DecodeString(valid.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		tampered := bytes.Clone(raw)
		tampered[i] ^= 1
		candidate := valid
		candidate.PayloadBase64 = base64Codec.EncodeToString(tampered)
		_, err := verify(candidate, fixedNow, 6, expectedAudience, keys())
		if err == nil {
			t.Fatalf("changing signed byte %d was accepted", i)
		}
	}
	// JSON rewriting with the same semantic values is *also* rejected. Only
	// canonical exact bytes are signed, not semantic JSON reserialization.
	altered := valid
	altered.PayloadBase64 = base64Codec.EncodeToString(append([]byte(" "), raw...))
	_, err = verify(altered, fixedNow, 6, expectedAudience, keys())
	assertCode(t, err, ReasonNotCanonical)
	sig, err := base64Codec.DecodeString(valid.SignatureBase64)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	altered = valid
	altered.SignatureBase64 = base64Codec.EncodeToString(sig)
	_, err = verify(altered, fixedNow, 6, expectedAudience, keys())
	assertCode(t, err, ReasonInvalidSignature)
}

func TestSnapshotValidation(t *testing.T) {
	fixtureSnapshot, err := ParseSnapshot(fixture(t, "snapshot_unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	clone := func() Snapshot {
		s := fixtureSnapshot
		s.Decisions = append([]Decision(nil), s.Decisions...)
		s.Decisions[0].DestinationPorts = append([]uint16(nil), s.Decisions[0].DestinationPorts...)
		return s
	}
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"missing_scope", func(s *Snapshot) { s.Audience.ServiceGroup = "" }},
		{"zero_revision", func(s *Snapshot) { s.Revision = 0 }},
		{"bad_cidr", func(s *Snapshot) { s.Decisions[0].Source = "0.0.0.0/0" }},
		{"ipv6_ban_unsupported", func(s *Snapshot) { s.Decisions[0].Source = "2001:db8::1/128" }},
		{"noncanonical_ip", func(s *Snapshot) { s.Decisions[0].Source = "203.0.113.042/32" }},
		{"broad_prefix", func(s *Snapshot) { s.Decisions[0].Source = "203.0.113.0/24" }},
		{"empty_ports", func(s *Snapshot) { s.Decisions[0].DestinationPorts = nil }},
		{"duplicate_ports", func(s *Snapshot) { s.Decisions[0].DestinationPorts = []uint16{80, 80} }},
		{"unordered_ports", func(s *Snapshot) { s.Decisions[0].DestinationPorts = []uint16{8899, 443} }},
		{"zero_port", func(s *Snapshot) { s.Decisions[0].DestinationPorts = []uint16{0} }},
		{"broad_action", func(s *Snapshot) { s.Decisions[0].Action = "execute" }},
		{"missing_reason", func(s *Snapshot) { s.Decisions[0].ReasonCode = "" }},
		{"extra_long_lifetime", func(s *Snapshot) { s.ExpiresAt = s.IssuedAt.Add(MaxSnapshotTTL + time.Nanosecond) }},
		{"expired_decision", func(s *Snapshot) { s.Decisions[0].ExpiresAt = s.IssuedAt }},
		{"decision_after_snapshot", func(s *Snapshot) { s.Decisions[0].ExpiresAt = s.ExpiresAt.Add(time.Second) }},
		{"too_many", func(s *Snapshot) { s.Decisions = make([]Decision, MaxDecisions+1) }},
		{"duplicate_decision", func(s *Snapshot) { s.Decisions = append(s.Decisions, s.Decisions[0]) }},
		{"null_decisions", func(s *Snapshot) { s.Decisions = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := clone()
			tc.mutate(&s)
			assertCode(t, ValidateSnapshot(s), ReasonInvalidDecision)
		})
	}
	// Verify a structurally valid signed snapshot that contains a decision
	// already expired at the verification instant.
	s := clone()
	s.Decisions[0].ExpiresAt = s.IssuedAt.Add(time.Second)
	signed, err := SignSnapshot(s, testKey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = verify(signed, fixedNow, 6, expectedAudience, keys())
	assertCode(t, err, ReasonExpired)
	// Unknown fields are NEVER interpreted as extra privileges.
	data := bytes.Replace(fixture(t, "snapshot_unsigned.json"), []byte(`"key_id":`), []byte(`"shell_command":"whoami","key_id":`), 1)
	_, err = ParseSnapshot(data)
	assertCode(t, err, ReasonMalformed)
	data = bytes.Repeat([]byte("x"), MaxSnapshotBytes+1)
	_, err = ParseSnapshot(data)
	assertCode(t, err, ReasonOversized)
}

func TestEvidenceFixturesAndValidation(t *testing.T) {
	raw, err := DecodeEvidence(fixture(t, "evidence_unverified.json"), "lab-node-a", fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeEvidence(fixture(t, "evidence_verified.json"), "lab-node-a", fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := DecodeEvidence(fixture(t, "evidence_udp_unverified.json"), "lab-node-a", fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	established, err := DecodeEvidence(fixture(t, "evidence_established.json"), "lab-node-a", fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if udp.ProofLevel != ProofUnverifiedLog || established.ProofLevel != ProofEstablishedConnection {
		t.Fatal("UDP and established TCP evidence must remain distinguishable")
	}
	if raw.ProofLevel != ProofUnverifiedLog || verified.ProofLevel != ProofApplicationVerified {
		t.Fatal("proof tiers are not distinct")
	}
	_, err = DecodeEvidence(fixture(t, "evidence_verified.json"), "impersonating-node", fixedNow)
	assertCode(t, err, ReasonScopeMismatch)
	tests := []struct {
		name   string
		mutate func(*Evidence)
		code   ReasonCode
	}{
		{"stale", func(e *Evidence) { e.ObservedAt = fixedNow.Add(-MaxEventAge - time.Second) }, ReasonExpired},
		{"future", func(e *Evidence) { e.ObservedAt = fixedNow.Add(MaxClockSkew + time.Second) }, ReasonExpired},
		{"invalid_ip", func(e *Evidence) { e.SourceIP = "not-an-ip" }, ReasonInvalidEvidence},
		{"mapped_ipv4", func(e *Evidence) { e.SourceIP = "::ffff:203.0.113.42" }, ReasonInvalidEvidence},
		{"zero_count", func(e *Evidence) { e.Attempts = 0 }, ReasonInvalidEvidence},
		{"huge_count", func(e *Evidence) { e.Attempts = MaxEventAttempts + 1 }, ReasonInvalidEvidence},
		{"bad_window", func(e *Evidence) { e.WindowSeconds = 0 }, ReasonInvalidEvidence},
		{"long_window", func(e *Evidence) { e.WindowSeconds = int(MaxEventWindow.Seconds()) + 1 }, ReasonInvalidEvidence},
		{"unknown_proof", func(e *Evidence) { e.ProofLevel = "fully_trusted" }, ReasonInvalidEvidence},
		{"udp_false_established", func(e *Evidence) { e.Transport = TransportUDP; e.ProofLevel = ProofEstablishedConnection }, ReasonInvalidEvidence},
		{"bad_port", func(e *Evidence) { e.DestinationPorts = []uint16{0} }, ReasonInvalidEvidence},
		{"duplicate_port", func(e *Evidence) { e.DestinationPorts = []uint16{80, 80} }, ReasonInvalidEvidence},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := raw
			tc.mutate(&e)
			assertCode(t, ValidateEvidence(e, "lab-node-a", fixedNow), tc.code)
		})
	}
	_, err = DecodeEvidence([]byte(`{"schema":1,"shell_command":"echo hi"}`), "lab-node-a", fixedNow)
	assertCode(t, err, ReasonMalformed)
	duplicate := bytes.Replace(fixture(t, "evidence_unverified.json"), []byte(`"schema": 1`), []byte(`"schema": 1, "schema": 1`), 1)
	_, err = DecodeEvidence(duplicate, "lab-node-a", fixedNow)
	assertCode(t, err, ReasonMalformed)
	_, err = DecodeEvidence(bytes.Repeat([]byte("x"), MaxEventBytes+1), "lab-node-a", fixedNow)
	assertCode(t, err, ReasonOversized)
}

func TestAcknowledgementStates(t *testing.T) {
	for _, state := range []DecisionState{StateReceived, StateValidated, StateApplied, StateRejected, StateError} {
		a := Acknowledgement{Schema: SchemaVersion, NodeID: "lab-node-a", Revision: 7, State: state}
		if state == StateRejected || state == StateError {
			a.Reason = ReasonExpired
		}
		if err := ValidateAcknowledgement(a); err != nil {
			t.Fatal(err)
		}
	}
	assertCode(t, ValidateAcknowledgement(Acknowledgement{Schema: 1, NodeID: "lab-node-a", Revision: 7, State: StateRejected}), ReasonInvalidDecision)
	assertCode(t, ValidateAcknowledgement(Acknowledgement{Schema: 1, NodeID: "lab-node-a", Revision: 7, State: StateApplied, Reason: ReasonReplay}), ReasonInvalidDecision)
	assertCode(t, ValidateAcknowledgement(Acknowledgement{Schema: 1, NodeID: "lab-node-a", Revision: 7, State: "root_shell"}), ReasonInvalidDecision)
}

func TestCanonicalPayloadRejectsExtraAndDuplicateFields(t *testing.T) {
	valid := signedFixture(t)
	raw, err := base64Codec.DecodeString(valid.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate JSON fields are rejected even if a decoder would otherwise
	// keep one of their values; the payload differs from canonical bytes.
	mutated := bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
	v := valid
	v.PayloadBase64 = base64Codec.EncodeToString(mutated)
	_, err = verify(v, fixedNow, 6, expectedAudience, keys())
	assertCode(t, err, ReasonMalformed)
	mutated = bytes.Replace(raw, []byte(`"key_id":`), []byte(`"run":"shutdown -h now","key_id":`), 1)
	v.PayloadBase64 = base64Codec.EncodeToString(mutated)
	_, err = verify(v, fixedNow, 6, expectedAudience, keys())
	assertCode(t, err, ReasonMalformed)
}
