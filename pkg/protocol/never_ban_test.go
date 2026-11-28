package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func neverBanFixture() (NeverBanList, time.Time) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	return NeverBanList{
		Schema: SchemaVersion, Revision: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "fleet",
		Entries: []Protection{
			{CIDR: "2001:db8::/48", Category: ProtectionPeers},
			{CIDR: "192.0.2.0/24", Category: ProtectionInfrastructure},
		},
	}, now
}

func neverBanKeys(t *testing.T) (map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{"fleet": pub}, key
}

func TestNeverBanCanonicalAndSigned(t *testing.T) {
	list, now := neverBanFixture()
	keys, key := neverBanKeys(t)
	first, err := SignNeverBanList(list, key)
	if err != nil {
		t.Fatal(err)
	}
	list.Entries[0], list.Entries[1] = list.Entries[1], list.Entries[0]
	second, err := SignNeverBanList(list, key)
	if err != nil || first != second {
		t.Fatal("signature should be independent of entry order", err)
	}
	wire, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedNeverBanList(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyNeverBanUpdate(decoded, keys, NeverBanList{}, now)
	if err != nil || got.Revision != 1 || len(got.Entries) != 2 {
		t.Fatal(got, err)
	}
	if _, err := VerifyNeverBanList(decoded, keys, 1, now); Reason(err) != ReasonReplay {
		t.Fatal("replay accepted", err)
	}
	if _, err := VerifyNeverBanList(decoded, keys, 0, list.ExpiresAt); Reason(err) != ReasonExpired {
		t.Fatal("expired list accepted", err)
	}
	if _, err := VerifyNeverBanList(decoded, keys, 0, now.Add(-time.Minute)); Reason(err) != ReasonClockSkew {
		t.Fatal("future list accepted", err)
	}
	if _, err := VerifyNeverBanList(decoded, nil, 0, now); Reason(err) != ReasonUnknownSigner {
		t.Fatal("unknown signer accepted", err)
	}
	payload, err := base64Codec.DecodeString(decoded.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	decoded.PayloadBase64 = base64Codec.EncodeToString([]byte(strings.Replace(string(payload), "192.0.2.0/24", "192.0.3.0/24", 1)))
	if _, err := VerifyNeverBanList(decoded, keys, 0, now); Reason(err) != ReasonInvalidSignature {
		t.Fatal("tampered protection accepted", err)
	}
	// A different signature domain must never authorize a protection list.
	decoded = first
	decoded.SignatureBase64 = base64Codec.EncodeToString(ed25519.Sign(key, append([]byte(signedSnapshotDomain), payload...)))
	if _, err := VerifyNeverBanList(decoded, keys, 0, now); Reason(err) != ReasonInvalidSignature {
		t.Fatal("wrong signature domain accepted", err)
	}
}

func TestNeverBanAddOnlyEvenAfterExpiry(t *testing.T) {
	old, now := neverBanFixture()
	keys, key := neverBanKeys(t)
	now = now.Add(2 * time.Hour)
	next := old
	next.Revision++
	next.IssuedAt = now
	next.ExpiresAt = now.Add(time.Hour)
	next.Entries = []Protection{{CIDR: "192.0.2.0/24", Category: ProtectionInfrastructure}}
	envelope, err := SignNeverBanList(next, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNeverBanUpdate(envelope, keys, old, now); Reason(err) != ReasonScopeMismatch {
		t.Fatal("removed protection accepted", err)
	}
	next.Entries = append(append([]Protection(nil), old.Entries...), Protection{CIDR: "198.51.100.10/32", Category: ProtectionPartners})
	envelope, err = SignNeverBanList(next, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNeverBanUpdate(envelope, keys, old, now); err != nil {
		t.Fatal("valid additive update rejected", err)
	}
}

func TestNeverBanOverlapAndStaleGate(t *testing.T) {
	list, now := neverBanFixture()
	for _, source := range []string{"192.0.2.42/32", "192.0.0.0/16", "2001:db8::1/128", "2001:db8::/32"} {
		if err := CheckNeverBanSource(list, netip.MustParsePrefix(source), now); Reason(err) != ReasonProtectedSource {
			t.Errorf("overlap %s not rejected: %v", source, err)
		}
	}
	unrelated := netip.MustParsePrefix("198.51.100.5/32")
	if err := CheckNeverBanSource(list, unrelated, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckNeverBanSource(list, unrelated, list.ExpiresAt); Reason(err) != ReasonExpired {
		t.Fatal("stale list permits new bans", err)
	}
	if err := CheckNeverBanSource(NeverBanList{}, unrelated, now); err == nil {
		t.Fatal("missing list permits new bans")
	}
}

func TestNeverBanRejectsMalformedEntriesAndWire(t *testing.T) {
	list, _ := neverBanFixture()
	for _, cidr := range []string{"192.0.2.1/24", "::ffff:192.0.2.1/128", "0.0.0.0/0", "invalid"} {
		bad := list
		bad.Entries = []Protection{{CIDR: cidr, Category: ProtectionPeers}}
		if err := ValidateNeverBanList(bad); err == nil {
			t.Errorf("accepted malformed CIDR %s", cidr)
		}
	}
	bad := list
	bad.Entries = []Protection{list.Entries[0], list.Entries[0]}
	if err := ValidateNeverBanList(bad); err == nil {
		t.Fatal("duplicate accepted")
	}
	bad.Entries = []Protection{{CIDR: "192.0.2.0/24", Category: "unknown"}}
	if err := ValidateNeverBanList(bad); err == nil {
		t.Fatal("unknown category accepted")
	}
	bad.Entries = make([]Protection, MaxNeverBanEntries+1)
	if err := ValidateNeverBanList(bad); err == nil {
		t.Fatal("entry limit ignored")
	}
	for _, wire := range []string{
		`{"payload_b64":"a","payload_b64":"b","signature_b64":"c"}`,
		`{"payload_b64":"a","signature_b64":"b","extra":true}`,
		`{"payload_b64":"a"}`,
		`{"payload_b64":"a","signature_b64":"b"} {}`,
	} {
		if _, err := DecodeSignedNeverBanList([]byte(wire)); err == nil {
			t.Errorf("accepted malformed wire %s", wire)
		}
	}
}
