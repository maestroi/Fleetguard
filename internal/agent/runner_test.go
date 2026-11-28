package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	firewalldsensor "github.com/maestroi/Fleetguard/internal/sensor/firewalld"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type fakeClient struct {
	snapshot         protocol.SignedSnapshot
	fetchErr         error
	ackErr           error
	acknowledgements []protocol.Acknowledgement
}

func (f *fakeClient) Fetch(context.Context) (protocol.SignedSnapshot, error) {
	return f.snapshot, f.fetchErr
}
func (f *fakeClient) Acknowledge(_ context.Context, a protocol.Acknowledgement) error {
	f.acknowledgements = append(f.acknowledgements, a)
	return f.ackErr
}
func TestPollerBoundedRetryAndNoFalseAck(t *testing.T) {
	e, _, now, priv, _ := fixture(t, "observe")
	c := &fakeClient{snapshot: snapshot(t, priv, *now, 1, "203.0.113.42/32")}
	p := &Poller{Engine: e, Client: c}
	c.fetchErr = context.DeadlineExceeded
	if err := p.PollOnce(context.Background()); err == nil || e.Status().Revision != 0 {
		t.Fatal("offline changed policy")
	}
	c.fetchErr = nil
	c.ackErr = context.DeadlineExceeded
	if err := p.PollOnce(context.Background()); err == nil || p.pending == nil || p.pending.State != protocol.StateValidated {
		t.Fatal("pending bounded ack lost")
	}
	c.ackErr = nil
	if err := p.PollOnce(context.Background()); err != nil || p.pending != nil {
		t.Fatal("ack not retried", err)
	}
	c.snapshot.SignatureBase64 = "invalid"
	before := len(c.acknowledgements)
	if err := p.PollOnce(context.Background()); err == nil || len(c.acknowledgements) != before {
		t.Fatal("invalid signature was acknowledged as valid")
	}
	if e.Status().Revision != 1 {
		t.Fatal("bad signature replaced persisted policy")
	}
}
func TestPollDelayBackoffBounded(t *testing.T) {
	zero := func(int64) int64 { return 0 }
	if PollDelay(2*time.Second, 0, zero) != 2*time.Second {
		t.Fatal("bad base interval")
	}
	if PollDelay(2*time.Second, 3, zero) != 16*time.Second {
		t.Fatal("bad exponential backoff")
	}
	if PollDelay(10*time.Second, 100, zero) != time.Minute {
		t.Fatal("backoff must be capped at a minute")
	}
	withJitter := PollDelay(10*time.Second, 0, func(n int64) int64 { return n - 1 })
	if withJitter < 10*time.Second || withJitter > 12*time.Second {
		t.Fatal("jitter out of range")
	}
}
func TestPinnedTLSAndNodeCredentials(t *testing.T) {
	e, _, now, priv, _ := fixture(t, "observe")
	received := 0
	acks := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Fleetguard-Node-ID") != "lab-node-a" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 32) || r.URL.Query().Get("group") != "lab-ssh" {
			t.Error("missing authenticated identity/scope")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/snapshot":
			received++
			json.NewEncoder(w).Encode(snapshot(t, priv, *now, 1, "203.0.113.42/32"))
		case "/v1/ack":
			a := protocol.Acknowledgement{}
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil || a.State != protocol.StateValidated {
				t.Error("bad ack", err)
			}
			acks++
			json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cert := srv.Certificate()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	c := RuntimeConfig{NodeID: "lab-node-a", ServiceGroup: "lab-ssh", Mode: "observe", FirewallBackend: "simulated", ControllerURL: srv.URL, TLSCAFile: certPath}
	transport, err := NewTransport(c, strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	p := &Poller{Engine: e, Client: transport}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received != 1 || acks != 1 {
		t.Fatalf("transport fetch=%d ack=%d", received, acks)
	}
}
func TestConfigStrictModes(t *testing.T) {
	valid := RuntimeConfig{
		NodeID: "lab-node-a", ServiceGroup: "lab-ssh", Mode: "observe", FirewallBackend: "simulated",
		ControllerURL: "https://127.0.0.1:9443", TLSCAFile: "/tmp/ca.pem", TokenFile: "/tmp/token",
		TrustedKeysFile: "/tmp/trusted.json", SafetyPolicyFile: "/tmp/safety.json", StateDir: "/tmp/agent-state",
		PollIntervalSeconds: 5, ReconcileIntervalSeconds: 1, MaxOfflineAgeSeconds: 60,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.ControllerURL = "https://example.org:9443"
	if err := invalid.Validate(); err == nil {
		t.Fatal("public host allowed")
	}
	invalid = valid
	invalid.FirewallBackend = "firewalld"
	if err := invalid.Validate(); err == nil {
		t.Fatal("real backend allowed in observe mode")
	}
	invalid = valid
	invalid.Mode = "enforce"
	if err := invalid.Validate(); err == nil {
		t.Fatal("enforcement without lab attestation allowed")
	}
	invalid = valid
	invalid.ControllerURL = "http://127.0.0.1:9443"
	if err := invalid.Validate(); err == nil {
		t.Fatal("cleartext HTTP accepted")
	}
	for name, mutate := range map[string]func(*RuntimeConfig){
		"required without anchor": func(c *RuntimeConfig) { c.NeverBanRequired = true },
		"shared keys file":        func(c *RuntimeConfig) { c.NeverBanKeysFile = c.TrustedKeysFile },
		"relative anchor":         func(c *RuntimeConfig) { c.NeverBanKeysFile = "never-ban.json" },
	} {
		invalid = valid
		mutate(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := valid
	ok.NeverBanKeysFile, ok.NeverBanRequired = "/tmp/never-ban.json", true
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSensorEvidenceSubmissionViaPinnedTLS(t *testing.T) {
	received := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/evidence" || r.URL.Query().Get("group") != "lab-ssh" ||
			r.Header.Get("X-Fleetguard-Node-ID") != "lab-node-a" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 32) {
			t.Error("incorrect evidence request scope/auth")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxEventBytes+1))
		if err != nil {
			t.Error(err)
			return
		}
		ev, err := protocol.DecodeEvidence(wire, "lab-node-a", time.Now())
		if err != nil || ev.ProofLevel != protocol.ProofUnverifiedLog || ev.Observation != "firewalld_denied_packets" {
			t.Error("invalid/spoofable observation: ", err, ev)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		received++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":true,"duplicate":false}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := RuntimeConfig{NodeID: "lab-node-a", ServiceGroup: "lab-ssh", ControllerURL: server.URL, TLSCAFile: certFile}
	client, err := NewTransport(cfg, strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ev := protocol.Evidence{
		Schema: protocol.SchemaVersion, NodeID: "lab-node-a", EventID: "test-fw-1", DedupKey: "test-fw-1",
		ObservedAt: time.Now().UTC(), WindowSeconds: 10, SourceIP: "203.0.113.99", Service: "ssh",
		Transport: protocol.TransportTCP, DestinationPorts: []uint16{2222}, Observation: "firewalld_denied_packets",
		Attempts: 3, ProofLevel: protocol.ProofUnverifiedLog,
	}
	if err := client.SubmitEvidence(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if received != 1 {
		t.Fatalf("expected one controller evidence request, got %d", received)
	}
	ev.ProofLevel = protocol.ProofEstablishedConnection
	ev.Transport = protocol.TransportUDP
	if err := client.SubmitEvidence(context.Background(), ev); err == nil {
		t.Fatal("UDP packet log claimed established-connection proof")
	}
	if received != 1 {
		t.Fatal("sent locally invalid evidence")
	}
}
func TestSensorRuntimeOptInStrict(t *testing.T) {
	good := RuntimeConfig{
		NodeID: "lab-node-a", ServiceGroup: "lab-ssh", Mode: "observe", FirewallBackend: "simulated",
		ControllerURL: "https://127.0.0.1:9443", TLSCAFile: "/tmp/ca.pem", TokenFile: "/tmp/token",
		TrustedKeysFile: "/tmp/keys", SafetyPolicyFile: "/tmp/policy", StateDir: "/tmp/private-state",
		PollIntervalSeconds: 5, ReconcileIntervalSeconds: 1, MaxOfflineAgeSeconds: 60,
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.DeniedTraffic = &firewalldsensor.Config{Enabled: true, WindowSeconds: 5, MaxSources: 0}
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid unlimited sensor config accepted")
	}
	good.DeniedTraffic = &firewalldsensor.Config{
		Enabled: true, WindowSeconds: 10, MaxSources: 32, MaxPacketsPerWindow: 100,
		MaxReportsPerWindow: 16, Bindings: []firewalldsensor.Binding{{Service: "ssh", Transport: protocol.TransportTCP, Port: 2222}},
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}
