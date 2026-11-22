package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maestroi/Fleetguard/internal/controller/auth"
	"github.com/maestroi/Fleetguard/internal/controller/store"
	"github.com/maestroi/Fleetguard/internal/metrics"
)

// Run serves the explicitly configured private IP using TLS 1.3 only. There
// are no public defaults and no unauthenticated privileged endpoints.
func Run(ctx context.Context, c auth.ServerConfig) error {
	ctx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	registry, err := auth.LoadRegistry(c.RegistryFile)
	if err != nil {
		return fmt.Errorf("load registry: %w", err)
	}
	key, err := auth.LoadSigningKey(c.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	if err := auth.PrivateFile(c.TLSKeyFile); err != nil {
		return fmt.Errorf("TLS private key: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return err
	}
	db, err := store.Open(c.DatabaseFile)
	if err != nil {
		return fmt.Errorf("open SQLite: %w", err)
	}
	defer db.Close()
	if err := db.SetEvidenceRetention(c.EvidenceRetentionHours); err != nil {
		return err
	}
	controller := New(registry, db, c.SigningKeyID, key, time.Now, slog.Default())
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); controller.RunWriter(workerCtx.Done()) }()
	defer func() { cancelWorker(); <-workerDone }()
	if c.MetricsListen != "" {
		go func() {
			if err := metrics.Serve(ctx, c.MetricsListen, controller.MetricsRegistry()); err != nil {
				// Telemetry failure must not take down evidence ingest.
				slog.Error("metrics listener failed", "error", err)
			}
		}()
	}
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: controller.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	stopReload := make(chan os.Signal, 1)
	signal.Notify(stopReload, syscall.SIGHUP)
	defer signal.Stop(stopReload)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopReload:
				updated, err := auth.LoadRegistry(c.RegistryFile)
				if err == nil {
					err = controller.ReplaceRegistry(updated)
				}
				if err != nil {
					slog.Error("registry reload rejected", "error", err)
				} else {
					slog.Info("registry reloaded")
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("controller HTTPS listening", "address", c.Listen, "mode", "observe-only")
	err = srv.Serve(tlsLn)
	stopRun()
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
