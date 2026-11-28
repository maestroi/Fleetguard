package sdnotify

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestNotifyAndWatchdogInterval(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if sent, err := Notify("READY=1"); sent || err != nil {
		t.Fatal("no socket must be a silent no-op")
	}
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if sent, err := Notify("WATCHDOG=1"); !sent || err != nil {
		t.Fatal(sent, err)
	}
	buf := make([]byte, 64)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, err := listener.Read(buf)
	if err != nil || string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("got %q %v", buf[:n], err)
	}

	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "")
	if d, ok := WatchdogInterval(); !ok || d != 30*time.Second {
		t.Fatal(d, ok)
	}
	t.Setenv("WATCHDOG_PID", strconv.Itoa(1))
	if _, ok := WatchdogInterval(); ok {
		t.Fatal("watchdog for another PID must be ignored")
	}
	for _, bad := range []string{"", "0", "-5", "abc"} {
		t.Setenv("WATCHDOG_PID", "")
		t.Setenv("WATCHDOG_USEC", bad)
		if _, ok := WatchdogInterval(); ok {
			t.Fatalf("WATCHDOG_USEC=%q accepted", bad)
		}
	}
}
