package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/pkg/protocol"
)

// ConfigureNeverBan installs the independent protection trust anchor. Call
// only before starting Handler; the key is immutable for the server lifetime.
// The online server does not need the protection private key.
func (s *Server) ConfigureNeverBan(keyID string, key ed25519.PublicKey) error {
	if keyID == "" || keyID == s.keyID || len(key) != ed25519.PublicKeySize || len(s.signingKey) != ed25519.PrivateKeySize || bytes.Equal(key, s.signingKey.Public().(ed25519.PublicKey)) {
		return errors.New("never-ban distribution requires a distinct protection signer")
	}
	s.neverBanKeys = map[string]ed25519.PublicKey{keyID: append(ed25519.PublicKey(nil), key...)}
	return nil
}

// neverBan is fleet-wide and read-only. Authentication and revocation checks
// happen in Handler before this method. No operator metadata is sent to agents.
func (s *Server) neverBan(w http.ResponseWriter, r *http.Request) {
	if len(s.neverBanKeys) == 0 {
		problem(w, http.StatusNotFound, "never_ban_disabled")
		return
	}
	if r.URL.RawQuery != "" {
		problem(w, http.StatusBadRequest, "never_ban_query_not_supported")
		return
	}
	revision, err := s.db.ReadNeverBanRevision(0, s.neverBanKeys)
	if errors.Is(err, store.ErrNeverBanMissing) {
		problem(w, http.StatusServiceUnavailable, "never_ban_missing")
		return
	}
	if err != nil {
		s.storage.WithLabelValues("never_ban").Inc()
		s.log.Error("never-ban read failed", "error", err)
		problem(w, http.StatusServiceUnavailable, "never_ban_unavailable")
		return
	}
	now := s.now()
	if !revision.List.ExpiresAt.After(now) {
		problem(w, http.StatusServiceUnavailable, "never_ban_expired")
		return
	}
	if revision.List.IssuedAt.After(now.Add(protocol.MaxClockSkew)) || now.IsZero() {
		problem(w, http.StatusServiceUnavailable, "never_ban_clock_skew")
		return
	}
	// Hash the exact signed envelope fields so a different document can never
	// share a validator just because it reuses a revision number.
	digest := sha256.Sum256([]byte(revision.Envelope.PayloadBase64 + "." + revision.Envelope.SignatureBase64))
	etag := fmt.Sprintf("\"%x\"", digest)
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Fleetguard-Revision", fmt.Sprint(revision.List.Revision))
	w.Header().Set("X-Fleetguard-Expires-At", revision.List.ExpiresAt.UTC().Format(time.RFC3339Nano))
	// Exact validator only; clients must have independently verified and
	// durably retained the document before requesting a conditional response.
	// Never return 304 for expired or otherwise invalid data.
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	jsonResult(w, http.StatusOK, revision.Envelope)
}
