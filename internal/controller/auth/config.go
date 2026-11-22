// Package auth reads a local lab controller registry and authenticates agents
// with independently generated bearer credentials. Tokens are never stored in
// the manifest, and a client-supplied node ID is never an authority by itself.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const maxFile = 64 << 10

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type ServerConfig struct {
	Mode                   string `json:"mode"`
	Listen                 string `json:"listen"`
	TLSCertFile            string `json:"tls_cert_file"`
	TLSKeyFile             string `json:"tls_key_file"`
	DatabaseFile           string `json:"database_file"`
	RegistryFile           string `json:"registry_file"`
	SigningKeyFile         string `json:"signing_key_file"`
	SigningKeyID           string `json:"signing_key_id"`
	EvidenceRetentionHours int    `json:"evidence_retention_hours,omitempty"`
}

type Node struct {
	NodeID      string   `json:"node_id"`
	TokenSHA256 string   `json:"token_sha256"`
	Groups      []string `json:"groups"`
	Revoked     bool     `json:"revoked"`
	digest      [32]byte
}

type Group struct {
	Services []string `json:"services"`
}

type Registry struct {
	Nodes  []Node           `json:"nodes"`
	Groups map[string]Group `json:"groups"`
}

func strictFile(path string, limit int, target any) error {
	if path == "" {
		return errors.New("required file path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("file exceeds configured size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("extra or invalid JSON values")
	}
	return nil
}

// PrivateFile rejects group/world-accessible registry, private keys and dbs.
func PrivateFile(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be a regular file with no group/world permissions (chmod 600)", filepath.Base(path))
	}
	return nil
}

func LoadServer(path string) (ServerConfig, error) {
	var c ServerConfig
	if err := strictFile(path, maxFile, &c); err != nil {
		return c, err
	}
	if c.EvidenceRetentionHours == 0 {
		c.EvidenceRetentionHours = 24
	}
	if c.EvidenceRetentionHours < 1 || c.EvidenceRetentionHours > 24 {
		return c, errors.New("evidence retention must be 1-24 hours")
	}
	if c.Mode != "observe" {
		return c, errors.New("only observe mode is supported")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return c, errors.New("explicit IP:port listen address required")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || (!addr.IsLoopback() && !addr.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(addr)) || addr.Is4In6() || addr.IsUnspecified() {
		return c, errors.New("listen must be an explicit loopback/private IP, not a wildcard or public address")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return c, errors.New("invalid TCP listen port")
	}
	for _, p := range []string{c.TLSCertFile, c.TLSKeyFile, c.DatabaseFile, c.RegistryFile, c.SigningKeyFile} {
		if p == "" {
			return c, errors.New("all controller TLS, SQLite, registry and signing paths are required")
		}
	}
	if !idPattern.MatchString(c.SigningKeyID) {
		return c, errors.New("invalid signing key ID")
	}
	return c, nil
}

func LoadRegistry(path string) (Registry, error) {
	var r Registry
	if err := PrivateFile(path); err != nil {
		return r, err
	}
	if err := strictFile(path, maxFile, &r); err != nil {
		return r, err
	}
	if len(r.Nodes) == 0 || len(r.Nodes) > 256 || len(r.Groups) == 0 || len(r.Groups) > 32 {
		return r, errors.New("registry requires 1-256 nodes and 1-32 groups")
	}
	for k, g := range r.Groups {
		if !idPattern.MatchString(k) || len(g.Services) == 0 || len(g.Services) > 32 {
			return r, errors.New("invalid group or services")
		}
		seen := map[string]bool{}
		for _, v := range g.Services {
			if !idPattern.MatchString(v) || seen[v] {
				return r, errors.New("invalid/duplicate group service")
			}
			seen[v] = true
		}
	}
	seenNodes := map[string]bool{}
	seenTokens := map[[32]byte]bool{}
	for i := range r.Nodes {
		n := &r.Nodes[i]
		if !idPattern.MatchString(n.NodeID) || seenNodes[n.NodeID] || len(n.Groups) == 0 || len(n.Groups) > 16 {
			return r, errors.New("invalid/duplicate node or empty groups")
		}
		seenNodes[n.NodeID] = true
		raw, err := hex.DecodeString(n.TokenSHA256)
		if err != nil || len(raw) != sha256.Size {
			return r, errors.New("token_sha256 must be 64 hex characters")
		}
		copy(n.digest[:], raw)
		if seenTokens[n.digest] || n.digest == [32]byte{} {
			return r, errors.New("duplicate/empty token hash")
		}
		seenTokens[n.digest] = true
		seenGroups := map[string]bool{}
		for _, v := range n.Groups {
			if _, ok := r.Groups[v]; !ok || seenGroups[v] {
				return r, fmt.Errorf("node %s has unknown/duplicate group", n.NodeID)
			}
			seenGroups[v] = true
		}
	}
	return r, nil
}

func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	if err := PrivateFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 256 {
		return nil, errors.New("signing key file too large")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key must be base64-encoded Ed25519 64-byte private key")
	}
	key := ed25519.PrivateKey(raw)
	// Reject inconsistent seed/public halves instead of accepting a malformed key.
	rebuilt := ed25519.NewKeyFromSeed(key.Seed())
	if subtle.ConstantTimeCompare(rebuilt, key) != 1 {
		return nil, errors.New("Ed25519 seed and public key do not match")
	}
	return key, nil
}

// Authenticate checks all hashes (constant-time comparison). The separately
// supplied node header must match the identity derived from that token.
func (r Registry) Authenticate(nodeHeader, authorization string) (Node, bool) {
	if !idPattern.MatchString(nodeHeader) || !strings.HasPrefix(authorization, "Bearer ") {
		return Node{}, false
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\r\n \t") {
		return Node{}, false
	}
	digest := sha256.Sum256([]byte(token))
	matching := -1
	for i := range r.Nodes {
		if subtle.ConstantTimeCompare(digest[:], r.Nodes[i].digest[:]) == 1 {
			matching = i
		}
	}
	if matching < 0 {
		return Node{}, false
	}
	n := r.Nodes[matching]
	if n.Revoked || n.NodeID != nodeHeader {
		return Node{}, false
	}
	return n, true
}
func (r Registry) CanAccess(n Node, group, service string) bool {
	g, ok := r.Groups[group]
	if !ok {
		return false
	}
	authorized := false
	for _, v := range n.Groups {
		if v == group {
			authorized = true
		}
	}
	if !authorized {
		return false
	}
	if service == "" {
		return true
	}
	for _, v := range g.Services {
		if v == service {
			return true
		}
	}
	return false
}
