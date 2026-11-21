package firewalld

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	busName        = "org.fedoraproject.FirewallD1"
	objectPath     = dbus.ObjectPath("/org/fedoraproject/FirewallD1")
	configPath     = dbus.ObjectPath("/org/fedoraproject/FirewallD1/config")
	rootInterface  = busName
	ipsetInterface = busName + ".ipset"
	zoneInterface  = busName + ".zone"
)

// SystemClient uses the system bus directly, without shelling out to
// firewall-cmd or running privileged commands. Close when finished.
type SystemClient struct{ conn *dbus.Conn }

var _ Client = (*SystemClient)(nil)

func ConnectSystemBus() (*SystemClient, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect firewalld system D-Bus: %w", err)
	}
	return &SystemClient{conn: conn}, nil
}
func (c *SystemClient) Close() error { return c.conn.Close() }
func (c *SystemClient) call(ctx context.Context, iface, method string, args ...any) *dbus.Call {
	return c.conn.Object(busName, objectPath).CallWithContext(ctx, iface+"."+method, 0, args...)
}
func (c *SystemClient) property(ctx context.Context, path dbus.ObjectPath, iface, name string) (any, error) {
	var v dbus.Variant
	err := c.conn.Object(busName, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v)
	if err != nil {
		return nil, err
	}
	return v.Value(), nil
}
func (c *SystemClient) Status(ctx context.Context) (Status, error) {
	var s Status
	getString := func(path dbus.ObjectPath, iface, key string) (string, error) {
		v, err := c.property(ctx, path, iface, key)
		if err != nil {
			return "", err
		}
		x, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("D-Bus property %s is not string", key)
		}
		return x, nil
	}
	var err error
	s.State, err = getString(objectPath, rootInterface, "state")
	if err != nil {
		return s, err
	}
	s.Version, err = getString(objectPath, rootInterface, "version")
	if err != nil {
		return s, err
	}
	s.Backend, err = getString(configPath, rootInterface+".config", "FirewallBackend")
	if err != nil {
		return s, err
	}
	ipv4, err := c.property(ctx, objectPath, rootInterface, "IPv4")
	if err != nil {
		return s, err
	}
	s.IPv4, _ = ipv4.(bool)
	supported, err := c.property(ctx, objectPath, rootInterface, "IPSet")
	if err != nil {
		return s, err
	}
	s.IPSet, _ = supported.(bool)
	types, err := c.property(ctx, objectPath, rootInterface, "IPSetTypes")
	if err != nil {
		return s, err
	}
	s.IPSetTypes, _ = types.([]string)
	if err := c.call(ctx, zoneInterface, "getActiveZones").Store(&s.ActiveZones); err != nil {
		return s, err
	}
	return s, nil
}

type rawSetSettings struct {
	Version     string
	Short       string
	Description string
	Type        string
	Options     map[string]string
	Entries     []string
}

func (c *SystemClient) IPSetSettings(ctx context.Context, name string) (SetSettings, error) {
	var raw rawSetSettings
	if err := c.call(ctx, ipsetInterface, "getIPSetSettings", name).Store(&raw); err != nil {
		return SetSettings{}, err
	}
	return SetSettings{Type: raw.Type, Description: raw.Description, Options: raw.Options}, nil
}
func (c *SystemClient) Entries(ctx context.Context, name string) ([]string, error) {
	var result []string
	if err := c.call(ctx, ipsetInterface, "getEntries", name).Store(&result); err != nil {
		return nil, err
	}
	return result, nil
}
func (c *SystemClient) RichRules(ctx context.Context, zone string) ([]string, error) {
	var result []string
	if err := c.call(ctx, zoneInterface, "getRichRules", zone).Store(&result); err != nil {
		return nil, err
	}
	return result, nil
}
func (c *SystemClient) AddEntry(ctx context.Context, name, entry string) error {
	return c.call(ctx, ipsetInterface, "addEntry", name, entry).Err
}
func (c *SystemClient) RemoveEntry(ctx context.Context, name, entry string) error {
	return c.call(ctx, ipsetInterface, "removeEntry", name, entry).Err
}
func (c *SystemClient) AddRichRule(ctx context.Context, zone, rule string) error {
	return c.call(ctx, zoneInterface, "addRichRule", zone, rule, int32(0)).Err
}
func (c *SystemClient) RemoveRichRule(ctx context.Context, zone, rule string) error {
	return c.call(ctx, zoneInterface, "removeRichRule", zone, rule).Err
}
