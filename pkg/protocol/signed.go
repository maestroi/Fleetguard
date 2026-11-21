package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

// Domain separator prevents an Ed25519 signature from this wire format being
// reused as a signature on another Fleetguard message type or version.
const signedSnapshotDomain = "Fleetguard/signed-snapshot/v1\x00"

var base64Codec = base64.RawStdEncoding.Strict()

// canonicalPayload is deterministic for this fixed struct schema; map fields,
// arbitrary extensions and unknown fields are deliberately not supported.
func canonicalPayload(s Snapshot) ([]byte, error) {
	s.IssuedAt = s.IssuedAt.UTC()
	s.ExpiresAt = s.ExpiresAt.UTC()
	for i := range s.Decisions {
		s.Decisions[i].ExpiresAt = s.Decisions[i].ExpiresAt.UTC()
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fail(ReasonMalformed, "marshal snapshot: %v", err)
	}
	if len(b) > MaxSnapshotBytes {
		return nil, fail(ReasonOversized, "snapshot exceeds size limit")
	}
	return b, nil
}

// SignSnapshot signs canonical JSON bytes using an explicit Ed25519 domain.
// This helper is for the offline signing authority; agents only receive public
// keys. Keys must never be delivered by the untrusted controller response.
func SignSnapshot(s Snapshot, privateKey ed25519.PrivateKey) (SignedSnapshot, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedSnapshot{}, fail(ReasonInvalidSignature, "invalid signing private key")
	}
	if err := ValidateSnapshot(s); err != nil {
		return SignedSnapshot{}, err
	}
	payload, err := canonicalPayload(s)
	if err != nil {
		return SignedSnapshot{}, err
	}
	sig := ed25519.Sign(privateKey, append([]byte(signedSnapshotDomain), payload...))
	return SignedSnapshot{PayloadBase64: base64Codec.EncodeToString(payload), SignatureBase64: base64Codec.EncodeToString(sig)}, nil
}

// DecodeSignedSnapshot strictly accepts exactly two envelope fields. A signed
// payload is an opaque base64 blob, not a JSON object subject to reserialization.
func DecodeSignedSnapshot(wire []byte) (SignedSnapshot, error) {
	var out SignedSnapshot
	if len(wire) > MaxEnvelopeBytes {
		return out, fail(ReasonOversized, "signed envelope exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(wire))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return out, fail(ReasonMalformed, "expected envelope object")
	}
	seen := make(map[string]bool, 2)
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return SignedSnapshot{}, fail(ReasonMalformed, "invalid envelope key")
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return SignedSnapshot{}, fail(ReasonMalformed, "duplicate envelope field")
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
			return SignedSnapshot{}, fail(ReasonMalformed, "envelope values must be JSON strings")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return SignedSnapshot{}, fail(ReasonMalformed, "envelope values must be base64 strings")
		}
		switch key {
		case "payload_b64":
			out.PayloadBase64 = value
		case "signature_b64":
			out.SignatureBase64 = value
		default:
			return SignedSnapshot{}, fail(ReasonMalformed, "unknown envelope field")
		}
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return SignedSnapshot{}, fail(ReasonMalformed, "unterminated envelope")
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return SignedSnapshot{}, fail(ReasonMalformed, "trailing envelope data")
	}
	if !seen["payload_b64"] || !seen["signature_b64"] {
		return SignedSnapshot{}, fail(ReasonMalformed, "missing envelope field")
	}
	return out, nil
}

// VerifySignedSnapshot checks signature, strict v1 schema, timestamps, audience,
// and monotonic revision. lastRevision MUST be persisted by the agent across
// restarts (issue #9), and expected is from local trusted configuration.
// This does not authorize applying a decision: local allowlists and scopes are
// a separate mandatory gate (issue #7).
func VerifySignedSnapshot(envelope SignedSnapshot, trustedKeys map[string]ed25519.PublicKey, expected Audience, lastRevision uint64, now time.Time) (Snapshot, error) {
	if !validID(expected.ServiceGroup) || !validID(expected.NodeID) {
		return Snapshot{}, fail(ReasonScopeMismatch, "expected audience must include node and service group")
	}
	if len(envelope.PayloadBase64) > base64Codec.EncodedLen(MaxSnapshotBytes) || len(envelope.SignatureBase64) > base64Codec.EncodedLen(ed25519.SignatureSize) {
		return Snapshot{}, fail(ReasonOversized, "base64 envelope field exceeds limit")
	}
	payload, err := base64Codec.DecodeString(envelope.PayloadBase64)
	if err != nil || len(payload) > MaxSnapshotBytes {
		return Snapshot{}, fail(ReasonMalformed, "invalid base64 payload")
	}
	sig, err := base64Codec.DecodeString(envelope.SignatureBase64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Snapshot{}, fail(ReasonMalformed, "invalid Ed25519 signature encoding")
	}
	var s Snapshot
	if err := decodeJSON(payload, MaxSnapshotBytes, &s); err != nil {
		return Snapshot{}, err
	}
	if err := ValidateSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	canonical, err := canonicalPayload(s)
	if err != nil {
		return Snapshot{}, err
	}
	if !bytes.Equal(canonical, payload) {
		return Snapshot{}, fail(ReasonNotCanonical, "payload is not canonical v1 JSON")
	}
	key, exists := trustedKeys[s.KeyID]
	if !exists || len(key) != ed25519.PublicKeySize {
		return Snapshot{}, fail(ReasonUnknownSigner, "no trusted key with valid size")
	}
	if !ed25519.Verify(key, append([]byte(signedSnapshotDomain), payload...), sig) {
		return Snapshot{}, fail(ReasonInvalidSignature, "signature verification failed")
	}
	if s.Audience.ServiceGroup != expected.ServiceGroup || (s.Audience.NodeID != "" && s.Audience.NodeID != expected.NodeID) {
		return Snapshot{}, fail(ReasonScopeMismatch, "snapshot audience does not match local audience")
	}
	if s.Revision <= lastRevision {
		return Snapshot{}, fail(ReasonReplay, "revision is not greater than accepted revision")
	}
	if s.IssuedAt.After(now.Add(MaxClockSkew)) {
		return Snapshot{}, fail(ReasonClockSkew, "snapshot issued too far in the future")
	}
	if !s.ExpiresAt.After(now) {
		return Snapshot{}, fail(ReasonExpired, "snapshot is expired")
	}
	// A decision must still be live at acceptance; expired entries are never
	// silently reactivated by a still-valid enclosing snapshot.
	for _, d := range s.Decisions {
		if !d.ExpiresAt.After(now) {
			return Snapshot{}, fail(ReasonExpired, "snapshot contains expired decision")
		}
	}
	return s, nil
}
