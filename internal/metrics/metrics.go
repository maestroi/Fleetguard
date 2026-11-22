// Package metrics serves a read-only Prometheus endpoint on a separate,
// explicitly configured private listener. It exposes aggregated telemetry
// only: no administrative routes, no per-IP or per-decision labels.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// ValidateListen accepts only an explicit loopback, RFC 1918/ULA or Tailscale
// IP with a port. Wildcard and public binds are rejected.
func ValidateListen(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return errors.New("explicit IP:port listen address required")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || (!addr.IsLoopback() && !addr.IsPrivate() && !tailscaleCGNAT.Contains(addr)) || addr.Is4In6() || addr.IsUnspecified() {
		return errors.New("listen must be an explicit loopback/private IP, not a wildcard or public address")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("invalid TCP listen port")
	}
	return nil
}

// NewRegistry returns a private registry with Go runtime and process
// collectors. A per-instance registry keeps tests and binaries independent.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// Handler serves GET /metrics and nothing else.
func Handler(reg prometheus.Gatherer) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 5 * time.Second}))
	return mux
}

// Serve runs plain HTTP until ctx ends. TLS/auth belong to a private reverse
// proxy or the tailnet; the endpoint carries no secrets and accepts no input.
func Serve(ctx context.Context, listen string, reg prometheus.Gatherer) error {
	if err := ValidateListen(listen); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: Handler(reg), ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("metrics listening", "address", listen)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
