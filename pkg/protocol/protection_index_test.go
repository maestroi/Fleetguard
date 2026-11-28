package protocol

import (
	"crypto/ed25519"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// Property: the index agrees with a brute-force linear Overlaps scan for
// random IPv4/IPv6 protections and sources across all prefix lengths.
func TestProtectionIndexMatchesLinearScan(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	randPrefix := func(v6 bool) netip.Prefix {
		if v6 {
			var b [16]byte
			b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8 // 2001:db8::/32 documentation
			b[4], b[15] = byte(r.IntN(4)), byte(r.IntN(4))
			return netip.PrefixFrom(netip.AddrFrom16(b), 32+r.IntN(97)).Masked()
		}
		a := netip.AddrFrom4([4]byte{192, 0, 2, byte(r.IntN(256))})
		if r.IntN(2) == 0 {
			a = netip.AddrFrom4([4]byte{198, 51, byte(r.IntN(4)), byte(r.IntN(256))})
		}
		return netip.PrefixFrom(a, 8+r.IntN(25)).Masked()
	}
	for round := 0; round < 200; round++ {
		var prot []netip.Prefix
		for range r.IntN(40) {
			prot = append(prot, randPrefix(r.IntN(2) == 0))
		}
		idx := NewProtectionIndex(prot)
		for range 200 {
			src := randPrefix(r.IntN(2) == 0)
			want := false
			for _, p := range prot {
				want = want || p.Overlaps(src)
			}
			if got := idx.Overlaps(src); got != want {
				t.Fatalf("round %d: Overlaps(%s)=%v want %v (protections %v)", round, src, got, want, prot)
			}
		}
	}
}

func TestProtectionIndexEdgeCases(t *testing.T) {
	idx := NewProtectionIndex([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/48")})
	cases := map[string]bool{
		"192.0.2.7/32":         true,  // inside
		"192.0.0.0/16":         true,  // contains protection
		"192.0.3.0/32":         false, // adjacent
		"2001:db8::1/128":      true,
		"2001:db8:1::1/128":    false,
		"::ffff:192.0.2.7/128": false, // different family; mapped forms are rejected elsewhere
	}
	for src, want := range cases {
		if got := idx.Overlaps(netip.MustParsePrefix(src)); got != want {
			t.Errorf("%s: got %v want %v", src, got, want)
		}
	}
	if !idx.Overlaps(netip.Prefix{}) {
		t.Error("invalid source must fail closed")
	}
	var empty *ProtectionIndex
	if empty.Overlaps(netip.MustParsePrefix("192.0.2.1/32")) || empty.Len() != 0 {
		t.Error("nil index protects nothing")
	}
}

func BenchmarkProtectionIndex4096(b *testing.B) {
	var prot []netip.Prefix
	for i := range 4096 {
		prot = append(prot, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24))
	}
	idx := NewProtectionIndex(prot)
	src := netip.MustParsePrefix("203.0.113.9/32")
	for b.Loop() {
		idx.Overlaps(src)
	}
}

// FuzzNeverBanDecode: untrusted wire bytes must never panic and never
// verify without the signer's key.
func FuzzNeverBanDecode(f *testing.F) {
	f.Add([]byte(`{"payload_b64":"e30","signature_b64":"AA"}`))
	f.Add([]byte(`{}`))
	keys := map[string]ed25519.PublicKey{"fleet": make([]byte, ed25519.PublicKeySize)}
	f.Fuzz(func(t *testing.T, wire []byte) {
		env, err := DecodeSignedNeverBanList(wire)
		if err != nil {
			return
		}
		if _, err := VerifyNeverBanList(env, keys, 0, time.Now()); err == nil {
			t.Fatal("verified under an all-zero key")
		}
		_, _ = DecodeNeverBanUnverified(env)
	})
}
