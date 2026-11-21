// Package config validates local, observe-only bootstrap configuration.
// No remote input can enable firewall enforcement in this release.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

const (
	ModeObserve      = "observe"
	BackendSimulated = "simulated"
	maxConfigBytes   = 64 << 10
)

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Agent struct {
	NodeID          string `json:"node_id"`
	Mode            string `json:"mode"`
	FirewallBackend string `json:"firewall_backend"`
}

func (c Agent) Validate() error {
	if !nodeIDPattern.MatchString(c.NodeID) {
		return errors.New("node_id must be 1-64 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	}
	if c.Mode != ModeObserve {
		return fmt.Errorf("agent mode %q is unsupported: only %q is available", c.Mode, ModeObserve)
	}
	if c.FirewallBackend != BackendSimulated {
		return fmt.Errorf("firewall_backend %q is unsupported: only %q is available", c.FirewallBackend, BackendSimulated)
	}
	return nil
}

type Controller struct {
	Mode string `json:"mode"`
}

func (c Controller) Validate() error {
	if c.Mode != ModeObserve {
		return fmt.Errorf("controller mode %q is unsupported: only %q is available", c.Mode, ModeObserve)
	}
	return nil
}

func LoadAgent(path string) (Agent, error) {
	var c Agent
	if err := load(path, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func LoadController(path string) (Controller, error) {
	var c Controller
	if err := load(path, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

// load deliberately rejects unknown fields, extra JSON values, and large files.
func load(path string, target any) error {
	if path == "" {
		return errors.New("-config is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("config contains multiple JSON values")
		}
		return fmt.Errorf("trailing config data: %w", err)
	}
	return nil
}
