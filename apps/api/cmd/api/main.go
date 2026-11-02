// Command api is the PIN & biometric login backend. It FAILS CLOSED: any configuration or store problem exits
// non-zero before the listener opens (SEC-004, SEC-016, SEC-065). Secrets are never printed.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
	logx "github.com/cryptoapp/api/internal/platform/log"
	"github.com/cryptoapp/api/internal/server"
	"github.com/cryptoapp/api/internal/store"
)

func main() { os.Exit(run()) }

func run() int {
	log := logx.New(os.Stderr, slog.LevelInfo)
	auditLog := logx.New(os.Stdout, slog.LevelInfo) // SEC-061: the audit sink is stdout, operational logs go to stderr
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		// config errors never contain secret values; print them to stderr so the operator can fix the environment
		_, _ = os.Stderr.WriteString("configuration error:\n" + err.Error() + "\n")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Error("invalid DATABASE_URL", "component", "main", "err_class", "config")
		return 1
	}
	pc.MaxConns = cfg.DBMaxConns
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		log.Error("database pool failed", "component", "main", "err_class", "store")
		return 1
	}
	defer pool.Close()
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pctx)
	cancel()
	if err != nil {
		log.Error("database unreachable: refusing to start", "component", "main", "err_class", "store")
		return 1
	}
	// L-08: the runtime role must not be able to alter the append-only audit table.
	if can, err := store.New(pool).Q.CanModifyAudit(ctx); err != nil || can {
		log.Error("database role can modify audit_events (use the least-privilege role): refusing to start", "component", "main", "err_class", "config")
		return 1
	}
	if !config.IsLoopback(cfg.ListenAddr) && !cfg.TrustedProxy {
		log.Warn("listening beyond loopback over plain HTTP: PIN, tokens and the demo secret are readable on this network (trusted LAN only)", "component", "main", "listen", cfg.ListenAddr)
	}
	clk := clock.System{}
	if cfg.DemoMode {
		if err := server.SeedDemo(ctx, store.New(pool), cfg, clk); err != nil {
			log.Error("seeding demo users failed", "component", "main", "err_class", "store")
			return 1
		}
	}
	app, err := server.New(server.Options{Cfg: cfg, Pool: pool, Clk: clk, Log: log, AuditLog: auditLog})
	if err != nil {
		log.Error("server init failed", "component", "main", "err_class", "init")
		return 1
	}
	go server.RunMaintenance(ctx, app.Store, clk, log)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: app.Handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "component", "main", "listen", cfg.ListenAddr, "env", cfg.Env, "demo_mode", cfg.DemoMode)
	select {
	case <-ctx.Done():
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
		return 0
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "component", "main", "err_class", "listen")
			return 1
		}
		return 0
	}
}
