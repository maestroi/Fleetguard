package exposure

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

const maxProcBytes = 4 << 20

// ParseProcSockets reads the kernel's local socket tables without root,
// external scans, process environment, process names, or packet inspection.
// A listener alone is NEVER considered publicly reachable.
func ParseProcSockets(r io.Reader, transport protocol.Transport, ipv6 bool) ([]Listener, error) {
	if transport != protocol.TransportTCP && transport != protocol.TransportUDP {
		return nil, errors.New("unsupported protocol")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxProcBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcBytes {
		return nil, errors.New("kernel socket table exceeds bounded read limit")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 8192)
	first := true
	result := make([]Listener, 0)
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		addr, portHex, ok := strings.Cut(fields[1], ":")
		if !ok || len(addr) != (func() int {
			if ipv6 {
				return 32
			}
			return 8
		}()) {
			continue
		}
		number, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || number == 0 {
			continue
		}
		if transport == protocol.TransportTCP && fields[3] != "0A" {
			continue
		} // TCP LISTEN only
		if transport == protocol.TransportUDP && fields[3] != "07" {
			continue
		} // UDP bound sockets
		bind := "interface"
		if strings.Trim(addr, "0") == "" {
			bind = "wildcard"
		}
		if !ipv6 && strings.EqualFold(addr, "0100007F") {
			bind = "loopback"
		}
		if ipv6 && strings.EqualFold(addr, "00000000000000000000000001000000") {
			bind = "loopback"
		}
		if len(result) >= 8192 {
			return nil, errors.New("socket table exceeds listener limit")
		}
		result = append(result, Listener{Transport: transport, Port: uint16(number), Bind: bind})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
func readSocketTable(path string, transport protocol.Transport, ipv6 bool) ([]Listener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseProcSockets(f, transport, ipv6)
}

type DbusReadOnly interface {
	GetActiveZones(context.Context) (map[string]map[string][]string, error)
	GetPorts(context.Context, string) ([][]string, error)
	GetServices(context.Context, string) ([]string, error)
	GetRichRules(context.Context, string) ([]string, error)
	GetForwardPorts(context.Context, string) ([][]string, error)
}
type dbusObserver struct{ conn *dbus.Conn }

func (d dbusObserver) call(ctx context.Context, method string, args ...any) *dbus.Call {
	return d.conn.Object("org.fedoraproject.FirewallD1", dbus.ObjectPath("/org/fedoraproject/FirewallD1")).CallWithContext(ctx, method, 0, args...)
}
func (d dbusObserver) GetActiveZones(ctx context.Context) (map[string]map[string][]string, error) {
	var result map[string]map[string][]string
	err := d.call(ctx, "org.fedoraproject.FirewallD1.zone.getActiveZones").Store(&result)
	return result, err
}
func (d dbusObserver) GetPorts(ctx context.Context, zone string) ([][]string, error) {
	var result [][]string
	err := d.call(ctx, "org.fedoraproject.FirewallD1.zone.getPorts", zone).Store(&result)
	return result, err
}
func (d dbusObserver) GetServices(ctx context.Context, zone string) ([]string, error) {
	var result []string
	err := d.call(ctx, "org.fedoraproject.FirewallD1.zone.getServices", zone).Store(&result)
	return result, err
}
func (d dbusObserver) GetRichRules(ctx context.Context, zone string) ([]string, error) {
	var result []string
	err := d.call(ctx, "org.fedoraproject.FirewallD1.zone.getRichRules", zone).Store(&result)
	return result, err
}
func (d dbusObserver) GetForwardPorts(ctx context.Context, zone string) ([][]string, error) {
	var result [][]string
	err := d.call(ctx, "org.fedoraproject.FirewallD1.zone.getForwardPorts", zone).Store(&result)
	return result, err
}
func appendNote(c *Coverage, note string) {
	if len(c.Notes) < 32 {
		c.Notes = append(c.Notes, note)
	}
}

// InspectFirewalld uses ONLY D-Bus read methods. A reported configured allow
// is not proof of reachability; service definitions, rich rules, policies,
// source zones, direct nftables and cloud firewalls may alter its meaning.
func InspectFirewalld(ctx context.Context, client DbusReadOnly, o *Observed) error {
	zones, err := client.GetActiveZones(ctx)
	if err != nil {
		return err
	}
	if len(zones) > 32 {
		return errors.New("firewalld returned too many active zones")
	}
	o.Coverage.Firewalld = true
	for zone, entry := range zones {
		if !identifier.MatchString(zone) {
			appendNote(&o.Coverage, "invalid zone name in runtime settings")
			o.Coverage.Firewalld = false
			continue
		}
		ports, err := client.GetPorts(ctx, zone)
		if err != nil {
			return err
		}
		if len(ports) > 512 {
			return errors.New("zone port count exceeds read-only bound")
		}
		for _, pair := range ports {
			if len(pair) != 2 {
				appendNote(&o.Coverage, "unrecognized port tuple")
				continue
			}
			transport := protocol.Transport(pair[1])
			if transport != protocol.TransportTCP && transport != protocol.TransportUDP {
				continue
			}
			first, last, ok := strings.Cut(pair[0], "-")
			if !ok {
				last = first
			}
			start, err1 := strconv.ParseUint(first, 10, 16)
			end, err2 := strconv.ParseUint(last, 10, 16)
			if err1 != nil || err2 != nil || start == 0 || end < start {
				appendNote(&o.Coverage, "invalid firewalld port range")
				continue
			}
			if end-start > 1024 {
				appendNote(&o.Coverage, "large firewalld range summarized incompletely")
				end = start
			}
			for p := start; p <= end; p++ {
				if len(o.Paths) >= 8192 {
					appendNote(&o.Coverage, "firewalld port list truncated")
					o.Coverage.Firewalld = false
					return nil
				}
				o.Paths = append(o.Paths, Path{Direction: "ingress", Transport: transport, Port: uint16(p), Source: "any", Zone: zone, State: "configured_allow", Provenance: "firewall_runtime"})
			}
		}
		services, err := client.GetServices(ctx, zone)
		if err != nil {
			return err
		}
		rules, err := client.GetRichRules(ctx, zone)
		if err != nil {
			return err
		}
		forwards, err := client.GetForwardPorts(ctx, zone)
		if err != nil {
			return err
		}
		if len(services) > 0 {
			appendNote(&o.Coverage, fmt.Sprintf("%s: named services not expanded (partial firewall view)", zone))
		}
		if len(rules) > 0 {
			appendNote(&o.Coverage, fmt.Sprintf("%s: rich rule ordering/impact not determined", zone))
		}
		if len(forwards) > 0 {
			appendNote(&o.Coverage, fmt.Sprintf("%s: forward ports found; end-to-end NAT not verified", zone))
		}
		if len(entry["sources"]) > 0 {
			appendNote(&o.Coverage, fmt.Sprintf("%s: source-specific zone cannot be classified as public", zone))
		}
	}
	appendNote(&o.Coverage, "firewalld policy objects, built-in services, nftables ordering, Docker publishing and external reachability not exhaustively inspected")
	return nil
}

// ObserveLive is read-only: it never opens ports, runs firewall-cmd, mounts
// host paths, or uses a Docker socket. The caller sees incomplete coverage
// explicitly when system D-Bus or procfs are unavailable.
func ObserveLive(ctx context.Context) Observed {
	o := Observed{Schema: SchemaVersion, ObservedAt: time.Now().UTC(), Listeners: make([]Listener, 0), Paths: make([]Path, 0)}
	success := true
	for _, file := range []struct {
		path      string
		transport protocol.Transport
		ipv6      bool
	}{
		{"/proc/net/tcp", protocol.TransportTCP, false},
		{"/proc/net/tcp6", protocol.TransportTCP, true},
		{"/proc/net/udp", protocol.TransportUDP, false},
		{"/proc/net/udp6", protocol.TransportUDP, true},
	} {
		listeners, err := readSocketTable(file.path, file.transport, file.ipv6)
		if err != nil {
			success = false
			appendNote(&o.Coverage, fmt.Sprintf("%s: unavailable or too large", file.path))
			continue
		}
		o.Listeners = append(o.Listeners, listeners...)
	}
	o.Coverage.Listeners = success
	appendNote(&o.Coverage, "local sockets are not proof of public reachability")
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		appendNote(&o.Coverage, "system D-Bus unavailable; firewalld not inspected")
	}
	if err == nil {
		defer conn.Close()
		timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = InspectFirewalld(timeoutCtx, dbusObserver{conn: conn}, &o)
		cancel()
		if err != nil {
			o.Coverage.Firewalld = false
			appendNote(&o.Coverage, "firewalld D-Bus inspection failed")
		}
		if !o.Coverage.Firewalld {
			o.Paths = nil
		} // incomplete read must never be presented as authoritative
	}
	// Deliberately no Docker socket, iptables or network reachability probe.
	o.Coverage.Forwarding = false
	o.Coverage.External = false
	appendNote(&o.Coverage, "container DNAT/FORWARD and upstream NAT/cloud rules unknown")
	return o
}
