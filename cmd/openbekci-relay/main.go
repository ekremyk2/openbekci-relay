// Command openbekci-relay is the OpenBekci push relay.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openbekci/openbekci-relay/internal/apns"
	"github.com/openbekci/openbekci-relay/internal/config"
	"github.com/openbekci/openbekci-relay/internal/fcm"
	"github.com/openbekci/openbekci-relay/internal/httpapi"
	"github.com/openbekci/openbekci-relay/internal/metrics"
	"github.com/openbekci/openbekci-relay/internal/push"
	"github.com/openbekci/openbekci-relay/internal/store"
)

var version = "dev"

const usage = `openbekci-relay: OpenBekci push relay

Usage:
  openbekci-relay serve                         run the relay (config from RELAY_* environment)
  openbekci-relay healthcheck                   exit 0 when the local relay answers /healthz
  openbekci-relay version
  openbekci-relay admin servers create --app-id ID [--name N] [--daily-quota N] [--unverified]
  openbekci-relay admin servers list
  openbekci-relay admin servers disable|enable|revoke SERVER_ID
  openbekci-relay admin invites create [--manual] [--ttl 168h] [--note TEXT]
  openbekci-relay admin invites list
  openbekci-relay admin invites revoke INVITE_ID
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "version":
		_, _ = fmt.Fprintln(stdout, version)
	case "admin":
		err = admin(args[1:], stdout)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// buildSenders turns the app configuration into the sender registry.
func buildSenders(cfg config.Config, log *slog.Logger) (*push.Registry, error) {
	reg := push.NewRegistry()
	for _, a := range cfg.Apps {
		if cfg.DevLogSender {
			ls := push.LogSender{Log: log}
			reg.Set(a.ID, push.KindFCM, ls)
			reg.Set(a.ID, push.KindAPNs, ls)
			continue
		}
		if a.FCMCredentials != nil {
			c, err := fcm.ParseCredentials(a.FCMCredentials)
			if err != nil {
				return nil, fmt.Errorf("app %s: %w", a.ID, err)
			}
			s, err := fcm.New(c, fcm.Options{})
			if err != nil {
				return nil, fmt.Errorf("app %s: %w", a.ID, err)
			}
			reg.Set(a.ID, push.KindFCM, s)
		}
		if a.APNsKey != nil {
			s, err := apns.New(apns.Config{KeyPEM: a.APNsKey, KeyID: a.APNsKeyID, TeamID: a.APNsTeamID, Topic: a.APNsTopic, Sandbox: a.APNsSandbox}, apns.Options{})
			if err != nil {
				return nil, fmt.Errorf("app %s: %w", a.ID, err)
			}
			reg.Set(a.ID, push.KindAPNs, s)
		}
	}
	return reg, nil
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	st, err := store.Open(cfg.DBPath, nil)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	m := metrics.New()
	senders, err := buildSenders(cfg, log)
	if err != nil {
		return err
	}
	api := httpapi.New(httpapi.Deps{Cfg: cfg, Store: st, Senders: senders, Log: log, Metrics: m})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go purgeLoop(ctx, st, log)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("relay listening", "addr", cfg.Listen, "version", version, "apps", len(cfg.Apps), "enrollment", cfg.Enrollment, "dev_log_sender", cfg.DevLogSender)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}

func purgeLoop(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.Purge(ctx); err != nil && ctx.Err() == nil {
				log.Warn("purge failed", "error_class", "store_error")
			}
		}
	}
}

// healthcheck probes the local listener; it is what the container HEALTHCHECK
// runs because the image has no curl.
func healthcheck() error {
	cfg, err := config.LoadAdmin()
	if err != nil {
		return err
	}
	addr := cfg.Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
