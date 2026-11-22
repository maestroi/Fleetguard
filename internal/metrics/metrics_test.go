package metrics

import "testing"

func TestValidateListen(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:9100": true, "10.0.0.5:9100": true, "100.101.102.103:9100": true, "[::1]:9100": true,
		"0.0.0.0:9100": false, ":9100": false, "8.8.8.8:9100": false, "localhost:9100": false,
		"127.0.0.1": false, "127.0.0.1:0": false, "[::ffff:10.0.0.1]:9100": false, "[::]:9100": false,
	} {
		if err := ValidateListen(addr); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
	}
}
