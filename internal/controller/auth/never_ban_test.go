package auth

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestNeverBanServerConfigOptIn(t *testing.T) {
	c := ServerConfig{Mode: "observe", Listen: "127.0.0.1:9443", TLSCertFile: "cert", TLSKeyFile: "key", DatabaseFile: "db", RegistryFile: "reg", SigningKeyFile: "signer", SigningKeyID: "policy"}
	path := filepath.Join(t.TempDir(), "server.json")
	pub := filepath.Join(t.TempDir(), "fleet.pub")
	for _, tc := range []struct {
		id   string
		file string
		ok   bool
	}{
		{"", "", true},
		{"fleet", "", false},
		{"", pub, false},
		{"policy", pub, false},
		{"bad id", pub, false},
		{"fleet", "relative.pub", false},
		{"fleet", pub, true},
	} {
		c.NeverBanKeyID = tc.id
		c.NeverBanPublicKeyFile = tc.file
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		testWrite(t, path, raw)
		if _, err := LoadServer(path); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}
