package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

func TestNeverBanDistribution(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "private", "controller.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policyPub, policyKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime
	registry := registryWithHashes(t)
	s := New(registry, db, "policy", policyKey, func() time.Time { return now }, nil)
	if err := s.ConfigureNeverBan("fleet", policyPub); err == nil {
		t.Fatal("accepted shared policy key")
	}
	if err := s.ConfigureNeverBan("policy", pub); err == nil {
		t.Fatal("accepted shared policy key ID")
	}
	call := func(method, path, node, token, etag string, secure bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		if secure {
			req.TLS = &tls.ConnectionState{}
		}
		req.Header.Set("X-Fleetguard-Node-ID", node)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("If-None-Match", etag)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	const path = "/v1/never-ban"
	if w := call("GET", path, "lab-a", tokenA, "", true); w.Code != 404 {
		t.Fatal("disabled endpoint", w.Code)
	}
	if err := s.ConfigureNeverBan("fleet", pub); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", path, "lab-a", tokenA, "", true); w.Code != 503 {
		t.Fatal("missing list", w.Code)
	}
	entry := protocol.Protection{CIDR: "192.0.2.0/24", Category: protocol.ProtectionPeers}
	first, err := db.UpdateNeverBan([]protocol.Protection{entry}, false, "uid:1", "private operator reason", "fleet", key, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a := call("GET", path, "lab-a", tokenA, "", true)
	b := call("GET", path, "lab-b", tokenB, "", true)
	if a.Code != 200 || b.Code != 200 || !bytes.Equal(a.Body.Bytes(), b.Body.Bytes()) {
		t.Fatal("agents did not receive identical fleet document", a.Code, b.Code)
	}
	if bytes.Contains(a.Body.Bytes(), []byte("private operator reason")) || a.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("metadata leaked or unsafe caching")
	}
	wire, err := protocol.DecodeSignedNeverBanList(a.Body.Bytes())
	if err != nil || wire != first.Envelope {
		t.Fatal(wire, err)
	}
	keys := map[string]ed25519.PublicKey{"fleet": pub}
	if _, err := protocol.VerifyNeverBanUpdate(wire, keys, protocol.NeverBanList{}, now); err != nil {
		t.Fatal(err)
	}
	etag := a.Header().Get("ETag")
	if etag == "" || a.Header().Get("X-Fleetguard-Revision") != "1" {
		t.Fatal("missing revision or ETag")
	}
	if w := call("GET", path, "lab-a", tokenA, etag, true); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal("conditional fetch", w.Code)
	}
	for _, tc := range []struct {
		method string
		path   string
		node   string
		token  string
		secure bool
		status int
	}{
		{"GET", path, "lab-a", tokenB, true, 401},
		{"GET", path, "lab-a", "", true, 401},
		{"GET", path, "lab-a", tokenA, false, 426},
		{"GET", path + "?revision=1", "lab-a", tokenA, true, 400},
		{"POST", path, "lab-a", tokenA, true, 405},
	} {
		if w := call(tc.method, tc.path, tc.node, tc.token, etag, tc.secure); w.Code != tc.status {
			t.Errorf("%+v: status %d", tc, w.Code)
		}
	}
	now = now.Add(time.Hour)
	if w := call("GET", path, "lab-a", tokenA, etag, true); w.Code != 503 || w.Header().Get("ETag") != "" {
		t.Fatal("expired list returned conditional success", w.Code)
	}
	if _, err := db.UpdateNeverBan(nil, true, "uid:1", "renew", "fleet", key, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", path, "lab-a", tokenA, etag, true); w.Code != 200 || w.Header().Get("ETag") == etag || w.Header().Get("X-Fleetguard-Revision") != "2" {
		t.Fatal("renewal was not published", w.Code)
	}
	registry.Nodes[0].Revoked = true
	if err := s.ReplaceRegistry(registry); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", path, "lab-a", tokenA, etag, true); w.Code != 401 {
		t.Fatal("revoked agent received document", w.Code)
	}
	if w := call("GET", path, "lab-b", tokenB, "", true); w.Code != 200 {
		t.Fatal("unrevoked agent lost access", w.Code)
	}
	// The current revision must not be distributed under a wrong trust anchor.
	if err := s.ConfigureNeverBan("fleet", policyPub); err == nil {
		t.Fatal("policy key reused")
	}
	_, wrong, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureNeverBan("fleet", wrong.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", path, "lab-b", tokenB, "", true); w.Code != 503 {
		t.Fatal("unverifiable list was served", w.Code)
	}
}
