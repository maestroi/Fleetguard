package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
}
