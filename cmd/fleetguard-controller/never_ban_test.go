package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestNeverBanCLI(t *testing.T) {
	dir := t.TempDir()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, policy, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	publicPath := write("fleet.pub", []byte(base64.StdEncoding.EncodeToString(pub)))
	privatePath := write("fleet.key", []byte(base64.StdEncoding.EncodeToString(key)))
	policyPath := write("policy.key", []byte(base64.StdEncoding.EncodeToString(policy)))
	config := map[string]string{
		"mode": "observe", "listen": "127.0.0.1:9443",
		"tls_cert_file": "unused", "tls_key_file": "unused", "registry_file": "unused",
		"database_file": filepath.Join(dir, "private", "controller.sqlite"),
		"signing_key_file": policyPath, "signing_key_id": "policy",
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("server.json", raw)
	common := []string{"-config", configPath, "-key-id", "fleet", "-public-key", publicPath}
	var out bytes.Buffer
	run := func(command string, extra ...string) error {
		out.Reset()
		args := append([]string{command}, common...)
		return runNeverBan(append(args, extra...), &out)
	}
	if err := run("add", "-private-key", privatePath, "-reason", "peer inventory", "-category", "peers", "-cidr", "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	var first store.NeverBanRevision
	if err := json.Unmarshal(out.Bytes(), &first); err != nil || first.List.Revision != 1 {
		t.Fatal(first, err)
	}
	if err := run("add", "-private-key", privatePath, "-reason", "partner inventory", "-category", "partners", "-cidr", "198.51.100.1/32"); err != nil {
		t.Fatal(err)
	}
	// Read-only commands do not require access to either private key.
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if err := run("list", "-revision", "1"); err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Revision store.NeverBanRevision `json:"revision"`
		Expired  bool                   `json:"expired"`
	}
	if err := json.Unmarshal(out.Bytes(), &listed); err != nil || listed.Revision.List.Revision != 1 || listed.Expired {
		t.Fatal(listed, err)
	}
	if err := run("diff", "-from", "1"); err != nil {
		t.Fatal(err)
	}
	var diff struct {
		From  uint64                `json:"from_revision"`
		To    uint64                `json:"to_revision"`
		Added []protocol.Protection `json:"added"`
	}
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil || diff.From != 1 || diff.To != 2 || len(diff.Added) != 1 || diff.Added[0].CIDR != "198.51.100.1/32" {
		t.Fatal(diff, err)
	}
	if err := run("list", "-private-key", privatePath); err == nil {
		t.Fatal("read-only command accepted a private key flag")
	}
}
