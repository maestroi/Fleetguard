package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/maestroi/Fleetguard/pkg/protocol"
)

type Transport struct {
	http  *http.Client
	base  string
	token string
	node  string
	group string
}

// NewTransport authenticates the controller using system-independent pinned
// local CA roots and a per-node bearer token. No redirects, proxies, HTTP,
// insecure TLS mode, or controller-directed URLs are supported.
func NewTransport(c RuntimeConfig, token string) (*Transport, error) {
	pem, err := os.ReadFile(c.TLSCAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid/pempty trusted TLS CA")
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") },
		Transport: &http.Transport{
			Proxy: nil, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 15 * time.Second,
			DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		},
	}
	return &Transport{http: client, base: strings.TrimSuffix(c.ControllerURL, "/"), token: token, node: c.NodeID, group: c.ServiceGroup}, nil
}
func (t *Transport) endpoint(path string) string {
	q := url.Values{"group": {t.group}}
	return t.base + path + "?" + q.Encode()
}
func (t *Transport) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.endpoint(path), r)
	if err != nil {
		return nil, err
	}
	t.authorize(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller %s: HTTP %d", path, resp.StatusCode)
	}
	limit := int64(protocol.MaxEnvelopeBytes + 1)
	if body != nil {
		limit = 4 << 10
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if len(content) >= int(limit) {
		return nil, errors.New("controller response exceeds bound")
	}
	return content, nil
}
func (t *Transport) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-Fleetguard-Node-ID", t.node)
	req.Header.Set("Accept", "application/json")
}

// FetchNeverBan retrieves the fleet-wide protection list (no group query; the
// endpoint is fleet-wide). Callers must send etag only for a document they
// have already verified and persisted. The result is still untrusted until
// Engine.AcceptNeverBan verifies its signature against the separate anchor.
func (t *Transport) FetchNeverBan(ctx context.Context, etag string) (env protocol.SignedNeverBanList, newETag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+"/v1/never-ban", nil)
	if err != nil {
		return env, "", false, err
	}
	t.authorize(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return env, "", false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return env, etag, true, nil
	case http.StatusOK:
	default:
		return env, "", false, fmt.Errorf("controller /v1/never-ban: HTTP %d", resp.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxNeverBanWireBytes+1))
	if err != nil {
		return env, "", false, err
	}
	if len(content) > protocol.MaxNeverBanWireBytes {
		return env, "", false, errors.New("never-ban response exceeds bound")
	}
	env, err = protocol.DecodeSignedNeverBanList(content)
	return env, resp.Header.Get("ETag"), false, err
}
func (t *Transport) Fetch(ctx context.Context) (protocol.SignedSnapshot, error) {
	wire, err := t.request(ctx, "GET", "/v1/snapshot", nil)
	if err != nil {
		return protocol.SignedSnapshot{}, err
	}
	return protocol.DecodeSignedSnapshot(wire)
}
func (t *Transport) Acknowledge(ctx context.Context, ack protocol.Acknowledgement) error {
	if err := protocol.ValidateAcknowledgement(ack); err != nil {
		return err
	}
	raw, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	_, err = t.request(ctx, "POST", "/v1/ack", raw)
	return err
}

// SubmitEvidence sends a single capped, unverified sensor summary to the
// existing per-node authenticated controller. Source fields remain untrusted;
// no sensor event is turned into a local or fleet-wide block here.
func (t *Transport) SubmitEvidence(ctx context.Context, event protocol.Evidence) error {
	if err := protocol.ValidateEvidence(event, t.node, time.Now()); err != nil {
		return err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(raw) > protocol.MaxEventBytes {
		return errors.New("sensor event exceeds protocol size limit")
	}
	_, err = t.request(ctx, http.MethodPost, "/v1/evidence", raw)
	return err
}
func (t *Transport) Close() {
	if tr, ok := t.http.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}
