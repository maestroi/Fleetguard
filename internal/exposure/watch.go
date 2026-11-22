package exposure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
)

// Alert is local configuration drift only, NEVER a trust/reputation claim.
type Alert struct {
	Kind    string    `json:"kind"` // new, resolved
	At      time.Time `json:"at"`
	Finding Finding   `json:"finding"`
}
type tracked struct {
	first   time.Time
	last    time.Time
	finding Finding
	sent    bool
}
type Tracker struct {
	Grace   time.Duration
	entries map[string]tracked
}

func NewTracker(grace time.Duration) (*Tracker, error) {
	if grace < 0 || grace > 5*time.Minute {
		return nil, errors.New("grace must be between 0 and 5 minutes")
	}
	return &Tracker{Grace: grace, entries: make(map[string]tracked)}, nil
}

// Update provides stable finding IDs, an optional maintenance grace window
// and only emits changes. Missing sightings are resolved; an unchanged drift
// does not spam alerts on a 5-second polling loop.
func (t *Tracker) Update(report Report, now time.Time) []Alert {
	if t.entries == nil {
		t.entries = map[string]tracked{}
	}
	present := make(map[string]bool, len(report.Findings))
	alerts := make([]Alert, 0)
	for _, f := range report.Findings {
		present[f.ID] = true
		record, ok := t.entries[f.ID]
		if !ok {
			record = tracked{first: now}
		}
		record.last = now
		record.finding = f
		if !record.sent && now.Sub(record.first) >= t.Grace {
			alerts = append(alerts, Alert{Kind: "new", At: now, Finding: f})
			record.sent = true
		}
		t.entries[f.ID] = record
	}
	for id, record := range t.entries {
		if present[id] {
			continue
		}
		if record.sent {
			alerts = append(alerts, Alert{Kind: "resolved", At: now, Finding: record.finding})
		}
		delete(t.entries, id)
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Kind != alerts[j].Kind {
			return alerts[i].Kind < alerts[j].Kind
		}
		return alerts[i].Finding.ID < alerts[j].Finding.ID
	})
	return alerts
}

// FirewalldEvents listens only to change *signals*; it cannot modify a zone.
// A closed channel means the optional bus subscription is unavailable.
// Continuous polling remains mandatory if a signal is missed or D-Bus restarts.
func FirewalldEvents(ctx context.Context) (<-chan struct{}, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	iface := "org.fedoraproject.FirewallD1"
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(iface)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(iface + ".zone")); err != nil {
		conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 32)
	conn.Signal(signals)
	changes := make(chan struct{}, 1)
	go func() {
		defer conn.Close()
		defer close(changes)
		defer conn.RemoveSignal(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case signal, ok := <-signals:
				if !ok {
					return
				}
				if signal == nil {
					continue
				}
				// Match on exact signal namespaces to avoid unrelated bus traffic.
				if signal.Name != iface+".Reloaded" && signal.Name != iface+".DefaultZoneChanged" &&
					signal.Name != iface+".zone.PortAdded" && signal.Name != iface+".zone.PortRemoved" &&
					signal.Name != iface+".zone.ZoneUpdated2" && signal.Name != iface+".zone.ServiceAdded" &&
					signal.Name != iface+".zone.ServiceRemoved" && signal.Name != iface+".zone.RichRuleAdded" &&
					signal.Name != iface+".zone.RichRuleRemoved" && signal.Name != iface+".zone.ZoneOfInterfaceChanged" &&
					signal.Name != iface+".zone.ZoneOfSourceChanged" && signal.Name != iface+".zone.ForwardPortAdded" &&
					signal.Name != iface+".zone.ForwardPortRemoved" {
					continue
				}
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}()
	return changes, nil
}

type LiveScanner func(context.Context) Observed
type WatchResult struct {
	Report              Report  `json:"report"`
	Alerts              []Alert `json:"alerts"`
	Trigger             string  `json:"trigger"`
	LatencyMilliseconds int64   `json:"detection_lag_ms"`
}

// Watch evaluates immediately, on periodic socket sampling, on firewalld
// change signals with debounce, and at most every 60 seconds for a full pass.
// It returns after context cancellation; all outputs are purely informational.
func Watch(ctx context.Context, expected Effective, interval time.Duration, grace time.Duration, scan LiveScanner, send func(WatchResult) error) error {
	if interval < time.Second || interval > 60*time.Second || scan == nil || send == nil {
		return errors.New("watch: invalid interval or callbacks")
	}
	tracker, err := NewTracker(grace)
	if err != nil {
		return err
	}
	changes, err := FirewalldEvents(ctx)
	if err != nil {
		changes = nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	full := time.NewTicker(60 * time.Second)
	defer full.Stop()
	var debounce *time.Timer
	var fire <-chan time.Time
	if debounce != nil {
		defer debounce.Stop()
	}
	run := func(trigger string, since time.Time) error {
		obs := scan(ctx)
		report, err := Evaluate(expected, obs)
		if err != nil {
			return err
		}
		result := WatchResult{Report: report, Alerts: tracker.Update(report, obs.ObservedAt), Trigger: trigger}
		if !since.IsZero() {
			result.LatencyMilliseconds = time.Since(since).Milliseconds()
		}
		return send(result)
	}
	if err := run("startup", time.Time{}); err != nil {
		return fmt.Errorf("initial exposure scan: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := run("socket_poll", time.Time{}); err != nil {
				return err
			}
		case <-full.C:
			if err := run("periodic_full", time.Time{}); err != nil {
				return err
			}
		case _, ok := <-changes:
			if !ok {
				changes = nil
				continue
			}
			if debounce == nil {
				debounce = time.NewTimer(750 * time.Millisecond)
				fire = debounce.C
			} else if !debounce.Stop() {
				select {
				case <-debounce.C:
				default:
				}
			}
			if debounce != nil {
				debounce.Reset(750 * time.Millisecond)
			}
		case observedStart := <-fire:
			if err := run("firewalld_change", observedStart.Add(-750*time.Millisecond)); err != nil {
				return err
			}
			fire = nil
			if debounce != nil {
				debounce.Stop()
				debounce = nil
			}
		}
	}
}
