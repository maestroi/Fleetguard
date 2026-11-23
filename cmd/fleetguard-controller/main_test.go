//go:build linux && cgo

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/correlation"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestOfflineOperatorEvaluationPersistsAuditAndDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	registryPath := filepath.Join(dir, "registry.json")
	serverPath := filepath.Join(dir, "server.json")
	keyPath := filepath.Join(dir, "signing.key")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "sqlite", "db.sqlite")
	write := func(path string, data any) {
		t.Helper()
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	policy := correlation.Config{Schema: 1, Mode: "observe", Group: "public-rpc", WindowSeconds: 120, DecisionTTLSeconds: 60, MinNodes: 2, MinDomains: 2, MaxEvidence: 100, MaxCandidates: 10, NodeDomains: map[string]string{"a": "domain-a", "b": "domain-b"}, Scopes: []correlation.Scope{{Service: "public-rpc", Observation: "application_abuse", Transport: protocol.TransportTCP, Port: 8899}}, ProtectedSources: []string{}, SharedNATSources: []string{}}
	write(policyPath, policy)
	hash := func(s string) string { a := sha256.Sum256([]byte(s)); return hex.EncodeToString(a[:]) }
	registry := map[string]any{"groups": map[string]any{"public-rpc": map[string]any{"services": []string{"public-rpc"}}}, "nodes": []map[string]any{{"node_id": "a", "token_sha256": hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "groups": []string{"public-rpc"}}, {"node_id": "b", "token_sha256": hash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "groups": []string{"public-rpc"}}}}
	write(registryPath, registry)
	write(serverPath, map[string]any{"mode": "observe", "listen": "127.0.0.1:9443", "tls_cert_file": "/not/needed/for/offline", "tls_key_file": "/not/needed/for/offline", "database_file": dbPath, "registry_file": registryPath, "signing_key_file": keyPath, "signing_key_id": "lab-signer"})
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, node := range []string{"a", "b"} {
		e := protocol.Evidence{Schema: 1, EventID: node + "-event", NodeID: node, DedupKey: node + "-dedup", ObservedAt: now, WindowSeconds: 30, SourceIP: "172.29.50.13", Service: "public-rpc", Transport: protocol.TransportTCP, DestinationPorts: []uint16{8899}, Observation: "application_abuse", Attempts: 8, ProofLevel: protocol.ProofApplicationVerified}
		if _, err = db.Ingest(e, "public-rpc", now); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := evaluateOffline(serverPath, policyPath, "public-rpc", "", "172.29.50.0/24", &output); err != nil {
		t.Fatal(err)
	}
	var report correlation.Report
	if err = json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 || report.PublishedPolicies != 0 || report.RealFirewallWrites != 0 {
		t.Fatalf("unexpected operator report: %+v", report)
	}
	if err := evaluateOffline(serverPath, policyPath, "other", "", "", &bytes.Buffer{}); err == nil {
		t.Fatal("group mismatch allowed")
	}
	db, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	count, err := db.AuditCount()
	if err != nil || count != 4 {
		t.Fatalf("audit should record two ingests, candidate and evaluation: %d %v", count, err)
	}

	approval := report.Candidates[0].Decision.ID
	if err := evaluateOffline(serverPath, policyPath, "public-rpc", approval, "172.29.51.0/24", &bytes.Buffer{}); err == nil {
		t.Fatal("out-of-scope source approved")
	}
	if !isLocalAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback not treated as a controller address")
	}
	write(serverPath, map[string]any{"mode": "observe", "listen": "0.0.0.0:9443", "tls_cert_file": "/not/needed/for/offline", "tls_key_file": "/not/needed/for/offline", "database_file": dbPath, "registry_file": registryPath, "signing_key_file": keyPath, "signing_key_id": "lab-signer"})
	if err := evaluateOffline(serverPath, policyPath, "public-rpc", approval, "172.29.50.0/24", &bytes.Buffer{}); err == nil {
		t.Fatal("approval allowed with wildcard listener")
	}
	write(serverPath, map[string]any{"mode": "observe", "listen": "127.0.0.1:9443", "tls_cert_file": "/not/needed/for/offline", "tls_key_file": "/not/needed/for/offline", "database_file": dbPath, "registry_file": registryPath, "signing_key_file": keyPath, "signing_key_id": "lab-signer"})
	output.Reset()
	if err := evaluateOffline(serverPath, policyPath, "public-rpc", approval, "172.29.50.0/24", &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.PublishedPolicies != 2 || report.Mode != "operator_approved_lab" {
		t.Fatalf("approval report: %+v, err = %v", report, err)
	}

}
