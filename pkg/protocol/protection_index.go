package protocol

import (
	"net/netip"
	"slices"
)

// ProtectionIndex answers "does this source overlap any protected prefix?"
// in O(distinct prefix lengths + log n) instead of a linear scan. Two
// canonical prefixes overlap iff one contains the other, so a lookup checks:
//   - a protection containing the source: exact set hit on the source masked
//     to each protection length present in its address family;
//   - a protection inside the source: binary search for any protected
//     network address within the source range.
//
// It is immutable after construction and safe for concurrent reads.
type ProtectionIndex struct {
	set    map[netip.Prefix]struct{}
	sorted []netip.Prefix // all protections sorted by network address
	v4bits []int          // distinct IPv4 lengths present
	v6bits []int          // distinct IPv6 lengths present
}

// NewProtectionIndex indexes already validated canonical prefixes. Invalid
// entries are skipped by the caller's prior validation; here they are ignored.
func NewProtectionIndex(prefixes []netip.Prefix) *ProtectionIndex {
	idx := &ProtectionIndex{set: make(map[netip.Prefix]struct{}, len(prefixes))}
	var v4, v6 [129]bool
	for _, p := range prefixes {
		if !p.IsValid() || p != p.Masked() {
			continue
		}
		if _, dup := idx.set[p]; dup {
			continue
		}
		idx.set[p] = struct{}{}
		idx.sorted = append(idx.sorted, p)
		if p.Addr().Is4() {
			v4[p.Bits()] = true
		} else {
			v6[p.Bits()] = true
		}
	}
	slices.SortFunc(idx.sorted, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	for bits := range 129 {
		if v4[bits] {
			idx.v4bits = append(idx.v4bits, bits)
		}
		if v6[bits] {
			idx.v6bits = append(idx.v6bits, bits)
		}
	}
	return idx
}

// NeverBanIndex indexes every entry of a structurally valid list.
func NeverBanIndex(list NeverBanList) *ProtectionIndex {
	prefixes := make([]netip.Prefix, 0, len(list.Entries))
	for _, entry := range list.Entries {
		if p, err := netip.ParsePrefix(entry.CIDR); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return NewProtectionIndex(prefixes)
}

func (idx *ProtectionIndex) Len() int {
	if idx == nil {
		return 0
	}
	return len(idx.set)
}

// Overlaps reports whether source shares any address with a protection. An
// invalid source is treated as overlapping so callers fail closed.
func (idx *ProtectionIndex) Overlaps(source netip.Prefix) bool {
	if !source.IsValid() {
		return true
	}
	_, ok := idx.Match(source)
	return ok
}

// Match returns one protection overlapping a valid source, if any.
func (idx *ProtectionIndex) Match(source netip.Prefix) (netip.Prefix, bool) {
	if idx == nil || len(idx.set) == 0 || !source.IsValid() {
		return netip.Prefix{}, false
	}
	source = source.Masked()
	bits := idx.v6bits
	if source.Addr().Is4() {
		bits = idx.v4bits
	}
	for _, length := range bits {
		if length > source.Bits() {
			break
		}
		candidate := netip.PrefixFrom(source.Addr(), length).Masked()
		if _, ok := idx.set[candidate]; ok {
			return candidate, true
		}
	}
	i, _ := slices.BinarySearchFunc(idx.sorted, source.Addr(), func(p netip.Prefix, a netip.Addr) int { return p.Addr().Compare(a) })
	if i < len(idx.sorted) && source.Contains(idx.sorted[i].Addr()) {
		return idx.sorted[i], true
	}
	return netip.Prefix{}, false
}
