package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func testToken() string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
func validRegistry() Registry {
	hash := sha256.Sum256([]byte(testToken()))
	return Registry{Nodes: []Node{{NodeID: "lab-a", TokenSHA256: hex.EncodeToString(hash[:]), Groups: []string{"ssh"}}}, Groups: map[string]Group{"ssh": {Services: []string{"ssh"}}}}
}
func loadFixture(t *testing.T, r Registry) (Registry, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "registry.json")
	b, _ := json.Marshal(r)
	testWrite(t, p, b)
	got, err := LoadRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	return got, p
}
func TestCredentialIdentityAndRevocation(t *testing.T) {
	r, p := loadFixture(t, validRegistry())
	if _, ok := r.Authenticate("lab-a", "Bearer "+testToken()); !ok {
		t.Fatal("valid credential denied")
	}
	for _, tt := range []struct{ id, bearer string }{{"lab-b", "Bearer " + testToken()}, {"lab-a", "Bearer wrong"}, {"lab-a", ""}, {"lab-a", "Bearer " + testToken() + " "}} {
		if _, ok := r.Authenticate(tt.id, tt.bearer); ok {
			t.Fatalf("accepted unauthorized %+v", tt)
		}
	}
	n, _ := r.Authenticate("lab-a", "Bearer "+testToken())
	if !r.CanAccess(n, "ssh", "ssh") || r.CanAccess(n, "ssh", "rpc") || r.CanAccess(n, "rpc", "") {
		t.Fatal("group permissions incorrect")
	}
	r.Nodes[0].Revoked = true
	b, _ := json.Marshal(r)
	testWrite(t, p, b)
	loaded, err := LoadRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Authenticate("lab-a", "Bearer "+testToken()); ok {
		t.Fatal("revoked token authorized")
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(p); err == nil {
		t.Fatal("world-readable manifest allowed")
	}
}
func TestRegistryRejectsBadFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Registry)
	}{
		{"duplicate node", func(r *Registry) { r.Nodes = append(r.Nodes, r.Nodes[0]) }},
		{"unknown group", func(r *Registry) { r.Nodes[0].Groups = []string{"not-a-group"} }},
		{"bad token", func(r *Registry) { r.Nodes[0].TokenSHA256 = "bad" }},
		{"duplicate group", func(r *Registry) { r.Nodes[0].Groups = []string{"ssh", "ssh"} }},
		{"duplicate service", func(r *Registry) { r.Groups["ssh"] = Group{Services: []string{"ssh", "ssh"}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRegistry()
			tc.mutate(&r)
			p := filepath.Join(t.TempDir(), "registry.json")
			b, _ := json.Marshal(r)
			testWrite(t, p, b)
			if _, err := LoadRegistry(p); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}
func TestSigningKeyPermissionsAndConsistency(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "signing.key")
	testWrite(t, p, []byte(base64.StdEncoding.EncodeToString(key)+"\n"))
	if _, err := LoadSigningKey(p); err != nil {
		t.Fatal(err)
	}
	key[63] ^= 0x01
	testWrite(t, p, []byte(base64.StdEncoding.EncodeToString(key)))
	if _, err := LoadSigningKey(p); err == nil {
		t.Fatal("corrupted Ed25519 key accepted")
	}
}
func TestConfigRejectsPublicWildcardAndEnforce(t *testing.T) {
	c := ServerConfig{Mode: "observe", Listen: "127.0.0.1:9443", TLSCertFile: "cert", TLSKeyFile: "key", DatabaseFile: "db", RegistryFile: "reg", SigningKeyFile: "signer", SigningKeyID: "lab"}
	p := filepath.Join(t.TempDir(), "server.json")
	for _, addr := range []string{"0.0.0.0:9443", "8.8.8.8:9443", ":9443", "localhost:9443"} {
		c.Listen = addr
		b, _ := json.Marshal(c)
		testWrite(t, p, b)
		if _, err := LoadServer(p); err == nil {
			t.Fatalf("accepted unsafe listen %s", addr)
		}
	}
	c.Listen = "127.0.0.1:9443"
	c.Mode = "enforce"
	b, _ := json.Marshal(c)
	testWrite(t, p, b)
	if _, err := LoadServer(p); err == nil {
		t.Fatal("accepted enforce mode")
	}
	c.Mode = "observe"
	b, _ = json.Marshal(c)
	testWrite(t, p, b)
	if _, err := LoadServer(p); err != nil {
		t.Fatal(err)
	}
}
