package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"sort"
	"time"
)

// Fleet protections have a separate signature domain and lifetime from
// enforcement snapshots. A signed ban can never be interpreted as an allowlist.
const (
	neverBanDomain       = "fleetguard/never-ban/v1\x00"
	MaxNeverBanEntries   = 4096
	MaxNeverBanBytes     = 512 << 10
	MaxNeverBanWireBytes = 704 << 10
	MaxNeverBanTTL       = 24 * time.Hour
)

type ProtectionCategory string

const (
	ProtectionInfrastructure ProtectionCategory = "infrastructure"
	ProtectionPeers          ProtectionCategory = "peers"
	ProtectionPartners       ProtectionCategory = "partners"
	ProtectionEdge           ProtectionCategory = "edge"
)

// Protection identifies a canonical network and its independently auditable
// category. Overlapping networks in different categories are permitted.
type Protection struct {
	CIDR     string             `json:"cidr"`
	Category ProtectionCategory `json:"category"`
}

// NeverBanList is fleet-wide, not a permission to open a port or change local
// policy. Entries may only add protection to the previously accepted list.
type NeverBanList struct {
	Schema    int          `json:"schema"`
	Revision  uint64       `json:"revision"`
	IssuedAt  time.Time    `json:"issued_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Entries   []Protection `json:"entries"`
	KeyID     string       `json:"key_id"`
}

type SignedNeverBanList struct {
	PayloadBase64   string `json:"payload_b64"`
	SignatureBase64 string `json:"signature_b64"`
}

func validProtectionCategory(c ProtectionCategory) bool {
	switch c {
	case ProtectionInfrastructure, ProtectionPeers, ProtectionPartners, ProtectionEdge:
		return true
	}
	return false
}

func ValidateNeverBanList(list NeverBanList) error {
	if list.Schema != SchemaVersion {
		return fail(ReasonInvalidSchema, "unsupported never-ban schema")
	}
	if list.Revision == 0 || !validID(list.KeyID) {
		return fail(ReasonInvalidDecision, "invalid never-ban revision or key ID")
	}
	if list.IssuedAt.IsZero() || !list.ExpiresAt.After(list.IssuedAt) || list.ExpiresAt.Sub(list.IssuedAt) > MaxNeverBanTTL {
		return fail(ReasonInvalidDecision, "never-ban lifetime out of bounds")
	}
	if list.Entries == nil || len(list.Entries) > MaxNeverBanEntries {
		return fail(ReasonInvalidDecision, "never-ban entries missing or over limit")
	}
	seen := make(map[Protection]bool, len(list.Entries))
	for _, entry := range list.Entries {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.String() != entry.CIDR {
			return fail(ReasonInvalidDecision, "invalid canonical never-ban CIDR")
		}
		if !validProtectionCategory(entry.Category) || seen[entry] {
			return fail(ReasonInvalidDecision, "unknown category or duplicate protection")
		}
		seen[entry] = true
	}
	return nil
}

func canonicalNeverBanPayload(list NeverBanList) ([]byte, error) {
	if err := ValidateNeverBanList(list); err != nil {
		return nil, err
	}
	list.IssuedAt = list.IssuedAt.UTC()
	list.ExpiresAt = list.ExpiresAt.UTC()
	list.Entries = append(make([]Protection, 0, len(list.Entries)), list.Entries...)
	sort.Slice(list.Entries, func(i, j int) bool {
		if list.Entries[i].CIDR == list.Entries[j].CIDR {
			return list.Entries[i].Category < list.Entries[j].Category
		}
		return list.Entries[i].CIDR < list.Entries[j].CIDR
	})
	payload, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxNeverBanBytes {
		return nil, fail(ReasonOversized, "never-ban payload exceeds limit")
	}
	return payload, nil
}

func SignNeverBanList(list NeverBanList, key ed25519.PrivateKey) (SignedNeverBanList, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedNeverBanList{}, fail(ReasonUnknownSigner, "invalid private key length")
	}
	payload, err := canonicalNeverBanPayload(list)
	if err != nil {
		return SignedNeverBanList{}, err
	}
	signature := ed25519.Sign(key, append([]byte(neverBanDomain), payload...))
	return SignedNeverBanList{
		PayloadBase64:   base64Codec.EncodeToString(payload),
		SignatureBase64: base64Codec.EncodeToString(signature),
	}, nil
}

func DecodeSignedNeverBanList(wire []byte) (SignedNeverBanList, error) {
	var envelope SignedNeverBanList
	if err := decodeJSON(wire, MaxNeverBanWireBytes, &envelope); err != nil {
		return SignedNeverBanList{}, err
	}
	if envelope.PayloadBase64 == "" || envelope.SignatureBase64 == "" {
		return SignedNeverBanList{}, fail(ReasonMalformed, "missing never-ban envelope fields")
	}
	return envelope, nil
}

// VerifyNeverBanList verifies a new signed revision. The caller must persist
// the accepted watermark and prior entries atomically before using them.
func VerifyNeverBanList(envelope SignedNeverBanList, keys map[string]ed25519.PublicKey, lastRevision uint64, now time.Time) (NeverBanList, error) {
	if len(envelope.PayloadBase64) > base64Codec.EncodedLen(MaxNeverBanBytes) || len(envelope.SignatureBase64) > base64Codec.EncodedLen(ed25519.SignatureSize) {
		return NeverBanList{}, fail(ReasonOversized, "never-ban envelope exceeds limit")
	}
	payload, err := base64Codec.DecodeString(envelope.PayloadBase64)
	if err != nil || len(payload) > MaxNeverBanBytes {
		return NeverBanList{}, fail(ReasonMalformed, "invalid never-ban payload encoding")
	}
	signature, err := base64Codec.DecodeString(envelope.SignatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return NeverBanList{}, fail(ReasonMalformed, "invalid never-ban signature encoding")
	}
	var list NeverBanList
	if err := decodeJSON(payload, MaxNeverBanBytes, &list); err != nil {
		return NeverBanList{}, err
	}
	canonical, err := canonicalNeverBanPayload(list)
	if err != nil {
		return NeverBanList{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return NeverBanList{}, fail(ReasonNotCanonical, "never-ban payload is not canonical")
	}
	key, ok := keys[list.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return NeverBanList{}, fail(ReasonUnknownSigner, "unknown never-ban signer")
	}
	if !ed25519.Verify(key, append([]byte(neverBanDomain), payload...), signature) {
		return NeverBanList{}, fail(ReasonInvalidSignature, "never-ban signature verification failed")
	}
	if list.Revision <= lastRevision {
		return NeverBanList{}, fail(ReasonReplay, "never-ban revision is not newer")
	}
	if list.IssuedAt.After(now.Add(MaxClockSkew)) {
		return NeverBanList{}, fail(ReasonClockSkew, "never-ban list issued in the future")
	}
	if !list.ExpiresAt.After(now) {
		return NeverBanList{}, fail(ReasonExpired, "never-ban list expired")
	}
	return list, nil
}

// ValidateNeverBanTransition rejects removal even when the previous signed list
// has expired or the signer has rotated. The previous list MUST originate from
// trusted durable state. A fresh revision may renew the same entries.
func ValidateNeverBanTransition(previous, next NeverBanList) error {
	if err := ValidateNeverBanList(next); err != nil {
		return err
	}
	if previous.Revision == 0 {
		if len(previous.Entries) != 0 {
			return fail(ReasonMalformed, "missing prior never-ban revision")
		}
		return nil
	}
	if err := ValidateNeverBanList(previous); err != nil {
		return err
	}
	if next.Revision <= previous.Revision {
		return fail(ReasonReplay, "never-ban revision is not newer")
	}
	entries := make(map[Protection]bool, len(next.Entries))
	for _, entry := range next.Entries {
		entries[entry] = true
	}
	for _, entry := range previous.Entries {
		if !entries[entry] {
			return fail(ReasonScopeMismatch, "never-ban protection cannot be removed remotely")
		}
	}
	return nil
}

// VerifyNeverBanUpdate is the combined gate for fresh signed updates. Its
// result must be persisted before replacing previously accepted protections.
func VerifyNeverBanUpdate(envelope SignedNeverBanList, keys map[string]ed25519.PublicKey, previous NeverBanList, now time.Time) (NeverBanList, error) {
	next, err := VerifyNeverBanList(envelope, keys, previous.Revision, now)
	if err != nil {
		return NeverBanList{}, err
	}
	if err := ValidateNeverBanTransition(previous, next); err != nil {
		return NeverBanList{}, err
	}
	return next, nil
}

// CheckNeverBanSource rejects a proposed new ban if the protection list is
// missing, invalid, stale, or overlaps the proposed source. Local protections
// are still mandatory and are checked separately; this function cannot grant
// permission to enforce. Call only with an already authenticated list.
func CheckNeverBanSource(list NeverBanList, source netip.Prefix, now time.Time) error {
	if err := ValidateNeverBanList(list); err != nil {
		return err
	}
	if !list.ExpiresAt.After(now) {
		return fail(ReasonExpired, "never-ban protection is stale")
	}
	if list.IssuedAt.After(now.Add(MaxClockSkew)) {
		return fail(ReasonClockSkew, "never-ban list issued in the future")
	}
	if !source.IsValid() || source.Addr().Is4In6() || source != source.Masked() || source.Bits() == 0 {
		return fail(ReasonInvalidDecision, "invalid ban source prefix")
	}
	for _, entry := range list.Entries {
		protected, _ := netip.ParsePrefix(entry.CIDR)
		if source.Overlaps(protected) {
			return fail(ReasonScopeMismatch, "protected_source: source overlaps fleet protection")
		}
	}
	return nil
}
