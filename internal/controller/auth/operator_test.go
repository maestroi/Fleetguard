package auth

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestEvidenceRetentionConfigBounds(t *testing.T) {
	config := ServerConfig{Mode: "observe", Listen: "127.0.0.1:9443", TLSCertFile: "cert", TLSKeyFile: "key", DatabaseFile: "db", RegistryFile: "registry", SigningKeyFile: "key.private", SigningKeyID: "lab"}
	path := filepath.Join(t.TempDir(), "server.json")
	for _, tc := range []struct {
		hours    int
		ok       bool
		expected int
	}{{0, true, 24}, {1, true, 1}, {24, true, 24}, {25, false, 0}, {-2, false, 0}} {
		config.EvidenceRetentionHours = tc.hours
		data, _ := json.Marshal(config)
		testWrite(t, path, data)
		got, err := LoadServer(path)
		if (err == nil) != tc.ok {
			t.Fatalf("retention %d valid=%v error=%v", tc.hours, tc.ok, err)
		}
		if tc.ok && got.EvidenceRetentionHours != tc.expected {
			t.Fatalf("retention default/bound incorrect: %+v", got)
		}
	}
}
