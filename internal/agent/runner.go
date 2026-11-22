package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/maestroi/Fleetguard/internal/firewall"
	"github.com/maestroi/Fleetguard/internal/firewall/firewalld"
	"github.com/maestroi/Fleetguard/internal/firewall/mock"
	"github.com/maestroi/Fleetguard/internal/safety"
	firewalldsensor "github.com/maestroi/Fleetguard/internal/sensor/firewalld"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type Poller struct {
	Engine  *Engine
	Client  PolicyClient
	pending *protocol.Acknowledgement // bounded to one freshest ack; no unbounded buffering
}
type PolicyClient interface {
	Fetch(context.Context) (protocol.SignedSnapshot, error)
	Acknowledge(context.Context, protocol.Acknowledgement) error
}

func (p *Poller) PollOnce(ctx context.Context) error {
	if p.Engine == nil || p.Client == nil {
		return errors.New("agent poller missing engine or transport")
	}
	if p.pending != nil {
		if err := p.Client.Acknowledge(ctx, *p.pending); err == nil {
			p.pending = nil
		}
	}
	env, err := p.Client.Fetch(ctx)
	if err != nil {
		return err
	}
	p.Engine.MarkContact()
	receipt, acceptErr := p.Engine.Accept(ctx, env)
	if receipt.Revision > 0 {
		// A signed but locally rejected revision is reported as rejected/error;
		// never report applied unless the backend completed readback.
		p.pending = &receipt
		if err := p.Client.Acknowledge(ctx, receipt); err != nil {
			if acceptErr != nil {
				return fmt.Errorf("policy rejected: %v; ack failed: %w", acceptErr, err)
			}
			return fmt.Errorf("send policy ack: %w", err)
		}
		p.pending = nil
	}
	return acceptErr
}

// PollDelay adds per-client jitter and bounded exponential backoff. The
// periodic reconcile timer runs independently of network connectivity.
func PollDelay(base time.Duration, failures int, jitter func(int64) int64) time.Duration {
	if base < time.Second {
		base = time.Second
	}
	if failures < 0 {
		failures = 0
	}
	if failures > 5 {
		failures = 5
	}
	d := base
	for i := 0; i < failures; i++ {
		if d >= time.Minute/2 {
			d = time.Minute
			break
		}
		d *= 2
	}
	if d > time.Minute {
		d = time.Minute
	}
	window := int64(d / 5)
	if jitter == nil {
		jitter = rand.Int64N
	}
	if window > 0 {
		d += time.Duration(jitter(window + 1))
	}
	return d
}
func BuildRealBackend(c RuntimeConfig, policy safety.Policy) (firewall.Backend, func() error, error) {
	if c.Mode != "enforce" || c.FirewallBackend != "firewalld" || !c.HostINPUTVerified || c.LabConfirm != labAcknowledgement {
		return nil, nil, errors.New("explicit isolated-lab firewalld opt-in required")
	}
	bus, err := firewalld.ConnectSystemBus()
	if err != nil {
		return nil, nil, err
	}
	b, err := firewalld.New(bus, firewalld.Options{
		Zone: c.Zone, Audience: protocol.Audience{NodeID: c.NodeID, ServiceGroup: c.ServiceGroup},
		Policy: policy, Bindings: c.Bindings, HostINPUTVerified: c.HostINPUTVerified,
	})
	if err != nil {
		bus.Close()
		return nil, nil, err
	}
	return b, bus.Close, nil
}

// Run is intentionally a separate opt-in daemon path. The existing
// fleetguard-agent -config bootstrap continues to be rootless, one-shot and
// network-free. Real firewall writes require a root-owned lab config, policy,
// state dir, and explicit INPUT attestation; no default enables enforcement.
func Run(ctx context.Context, configPath string, out io.Writer) error {
	c, err := LoadRuntimeConfig(configPath)
	if err != nil {
		return err
	}
	if c.Mode == "enforce" {
		if err := safety.CheckRootOwnedFile(configPath); err != nil {
			return err
		}
	}
	policy, err := c.LoadPolicy()
	if err != nil {
		return err
	}
	if c.Mode == "enforce" && policy.Mode != "enforce" {
		return errors.New("real enforcement requires local safety mode enforce")
	}
	keys, err := LoadKeys(c.TrustedKeysFile, c.Mode == "enforce")
	if err != nil {
		return err
	}
	token, err := LoadToken(c.TokenFile, c.Mode == "enforce")
	if err != nil {
		return err
	}
	client, err := NewTransport(c, token)
	if err != nil {
		return err
	}
	defer client.Close()
	store := FileStore{Dir: c.StateDir, RequireRoot: c.Mode == "enforce"}
	var backend firewall.Backend
	var closeBackend func() error
	if c.Mode == "observe" {
		backend, err = mock.New(time.Now)
	} else {
		backend, closeBackend, err = BuildRealBackend(c, policy)
	}
	if err != nil {
		return err
	}
	if closeBackend != nil {
		defer closeBackend()
	}
	emergency := func() (bool, error) { return safety.Disabled(c.StateDir) }
	engine, err := NewEngine(EngineOptions{
		Audience: protocol.Audience{NodeID: c.NodeID, ServiceGroup: c.ServiceGroup},
		Keys:     keys, Policy: policy, Backend: backend, Store: store,
		Mode: c.Mode, BackendName: c.FirewallBackend, HostINPUTVerified: c.HostINPUTVerified,
		EmergencyDisabled: emergency, MaxOfflineAge: time.Duration(c.MaxOfflineAgeSeconds) * time.Second, Now: time.Now,
	})
	if err != nil {
		// If state recovery fails after a crash, do not leave unknown runtime
		// blocks installed until a human eventually repairs the state file.
		if c.Mode == "enforce" {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if removeErr := backend.RemoveOwned(cleanupCtx); removeErr != nil {
				slog.Error("unsafe recovery and owned cleanup failed", "error", removeErr)
			}
			cancel()
		}
		return err
	}
	poller := &Poller{Engine: engine, Client: client}
	var denied *firewalldsensor.Collector
	if c.DeniedTraffic != nil {
		denied, err = firewalldsensor.NewCollector(c.NodeID, *c.DeniedTraffic)
		if err != nil {
			return err
		}
		// Journal collection is opt-in and never calls Engine.AddLocal.
		// An optional telemetry reader cannot block policy expiry or management.
		go firewalldsensor.RunJournal(ctx, denied, client)
	}
	// A clean shutdown clears all temporary owned rules. A SIGKILL or power
	// failure CANNOT guarantee removal until the next restart/reconcile: run
	// this lab-only opt-in with independent console access and a watchdog.
	if c.Mode == "enforce" {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := backend.RemoveOwned(cleanupCtx); err != nil {
				slog.Error("owned firewall cleanup on shutdown failed", "error", err)
			}
		}()
	}
	tickInterval := time.Duration(c.ReconcileIntervalSeconds) * time.Second
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	poll := time.NewTimer(0)
	defer poll.Stop()
	failures := 0
	encoder := json.NewEncoder(out)
	previous := Status{}
	lastStatus := time.Time{}
	writeStatus := func() error {
		payload := struct {
			Status
			Sensor *firewalldsensor.Stats `json:"denied_traffic,omitempty"`
		}{Status: engine.Status()}
		if denied != nil {
			s := denied.Stats()
			payload.Sensor = &s
		}
		lastStatus = time.Now()
		return encoder.Encode(payload)
	}
	// Reconcile recovered, unexpired state or clear unknown runtime entries
	// before contacting any controller; never let a stale IP-set ban persist
	// as apparently valid after a restart.
	if err := engine.Tick(ctx); err != nil {
		slog.Error("initial local reconcile failed", "error", err)
	}
	if err := writeStatus(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := engine.Tick(ctx); err != nil {
				slog.Warn("local reconcile failed", "error", err)
			}
			status := engine.Status()
			if status != previous || (denied != nil && time.Since(lastStatus) >= 10*time.Second) {
				if err := writeStatus(); err != nil {
					return err
				}
				previous = status
			}
		case <-poll.C:
			if err := poller.PollOnce(ctx); err != nil {
				failures++
				slog.Warn("controller poll/validation failed", "error", err)
			} else {
				failures = 0
			}
			if err := engine.Tick(ctx); err != nil {
				slog.Warn("post-poll reconcile failed", "error", err)
			}
			if err := writeStatus(); err != nil {
				return err
			}
			poll.Reset(PollDelay(time.Duration(c.PollIntervalSeconds)*time.Second, failures, nil))
		}
	}
}
