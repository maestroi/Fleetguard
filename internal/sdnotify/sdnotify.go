// Package sdnotify implements the two pieces of the systemd notify protocol
// Fleetguard needs (READY/WATCHDOG/STOPPING datagrams and WatchdogSec
// discovery) with the standard library, avoiding a libsystemd dependency.
// Works with systemd >= 209 (RHEL/Alma/Rocky 8 ship 239).
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends one state datagram to $NOTIFY_SOCKET. Outside a Type=notify
// unit there is no socket: it returns (false, nil). A leading '@' (abstract
// namespace) is handled by the Go runtime.
func Notify(state string) (bool, error) {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return false, nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}

// WatchdogInterval returns WatchdogSec for this process, or false when the
// watchdog is disabled or addressed to another PID.
func WatchdogInterval() (time.Duration, bool) {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0, false
	}
	return time.Duration(usec) * time.Microsecond, true
}
