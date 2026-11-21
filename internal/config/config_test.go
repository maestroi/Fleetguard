package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAgent(t *testing.T) {
	valid := `{"node_id":"lab-node-a","mode":"observe","firewall_backend":"simulated"}`
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"valid", valid, true},
		{"enforcement forbidden", `{"node_id":"lab-node-a","mode":"enforce","firewall_backend":"simulated"}`, false},
		{"real backend forbidden", `{"node_id":"lab-node-a","mode":"observe","firewall_backend":"firewalld"}`, false},
		{"missing node", `{"mode":"observe","firewall_backend":"simulated"}`, false},
		{"invalid node", `{"node_id":"../etc","mode":"observe","firewall_backend":"simulated"}`, false},
		{"unknown field", `{"node_id":"lab-node-a","mode":"observe","firewall_backend":"simulated","token":"secret"}`, false},
		{"extra JSON", valid + ` {}`, false},
		{"malformed JSON", `{`, false},
		{"too large", valid + strings.Repeat(" ", maxConfigBytes), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadAgent(writeConfig(t, tt.text))
			if (err == nil) != tt.ok {
				t.Fatalf("LoadAgent() err = %v, want success = %t", err, tt.ok)
			}
		})
	}
}

func TestLoadController(t *testing.T) {
	for _, tt := range []struct {
		name string
		text string
		ok   bool
	}{
		{"valid", `{"mode":"observe"}`, true},
		{"enforcement forbidden", `{"mode":"enforce"}`, false},
		{"unknown field", `{"mode":"observe","listen":"0.0.0.0:8080"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadController(writeConfig(t, tt.text))
			if (err == nil) != tt.ok {
				t.Fatalf("LoadController() err = %v, want success = %t", err, tt.ok)
			}
		})
	}
}

func TestMissingConfig(t *testing.T) {
	if _, err := LoadAgent(""); err == nil {
		t.Fatal("empty -config should be rejected")
	}
	if _, err := LoadController(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing config should be rejected")
	}
}
