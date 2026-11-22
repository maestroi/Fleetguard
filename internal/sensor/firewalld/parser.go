// Package firewalld collects optional, bounded denied-packet telemetry.
// Kernel log lines contain attacker-controlled source fields; they are never
// authoritative proof of a connection, identity or trustworthy source IP.
package firewalld

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const MaxLineBytes = 2048

var (
	ErrIgnored    = errors.New("firewalld: unrelated or unsupported log")
	ErrMalformed  = errors.New("firewalld: invalid denied-packet log")
	zonePrefix    = regexp.MustCompile(`^filter_IN_[A-Za-z0-9_]{1,40}_(DROP|REJECT):$`)
	interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)
)

// Packet describes a single kernel claim, never a verified connection.
// Only host INPUT logs are accepted: OUT must be empty and IN nonempty.
type Packet struct {
	Source          netip.Addr
	Destination     netip.Addr
	InInterface     string
	Transport       protocol.Transport
	DestinationPort uint16
}

func deniedPrefix(token string) bool {
	return token == "FINAL_DROP:" || token == "FINAL_REJECT:" || zonePrefix.MatchString(token)
}

// ParseLine accepts only known IPv4 firewalld host INPUT kernel prefixes.
// All arbitrary logging prefixes, forwarded traffic, non-TCP/UDP, and
// invalid/ambiguous fields are discarded. Log source addresses are spoofable.
func ParseLine(line string) (Packet, error) {
	if len(line) == 0 || len(line) > MaxLineBytes || strings.ContainsRune(line, '\x00') {
		return Packet{}, ErrMalformed
	}
	words := strings.Fields(line)
	if len(words) > 65 {
		return Packet{}, ErrMalformed
	}
	pos := -1
	for i, word := range words {
		if deniedPrefix(word) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return Packet{}, ErrIgnored
	}
	fields := make(map[string]string, 16)
	for _, word := range words[pos+1:] {
		key, val, found := strings.Cut(word, "=")
		if !found {
			continue
		} // e.g. SYN, DF or kernel informational fields
		if key == "" || len(key) > 24 || len(val) > 128 {
			return Packet{}, ErrMalformed
		}
		if _, seen := fields[key]; seen && key != "LEN" {
			return Packet{}, ErrMalformed
		}
		fields[key] = val
	}
	in, out := fields["IN"], fields["OUT"]
	if _, ok := fields["OUT"]; !ok {
		return Packet{}, ErrMalformed
	}
	if in == "" || !interfaceName.MatchString(in) {
		return Packet{}, ErrMalformed
	}
	if out != "" {
		return Packet{}, ErrIgnored
	} // FORWARD, not host INPUT
	src, err := netip.ParseAddr(fields["SRC"])
	if err != nil || !src.Is4() || src.Is4In6() || src.String() != fields["SRC"] || src.IsUnspecified() || src.IsMulticast() || src.IsLoopback() || src.IsLinkLocalUnicast() {
		return Packet{}, ErrMalformed
	}
	dst, err := netip.ParseAddr(fields["DST"])
	if err != nil || !dst.Is4() || dst.Is4In6() || dst.String() != fields["DST"] || dst.IsUnspecified() || dst.IsMulticast() {
		return Packet{}, ErrMalformed
	}
	var transport protocol.Transport
	switch fields["PROTO"] {
	case "TCP":
		transport = protocol.TransportTCP
	case "UDP":
		transport = protocol.TransportUDP
	default:
		return Packet{}, ErrIgnored
	}
	port, err := strconv.ParseUint(fields["DPT"], 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != fields["DPT"] {
		return Packet{}, fmt.Errorf("%w: invalid destination port", ErrMalformed)
	}
	return Packet{Source: src, Destination: dst, InInterface: in, Transport: transport, DestinationPort: uint16(port)}, nil
}
