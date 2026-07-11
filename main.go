// vps-user-portal: an admin-gated web portal that provisions SSO users
// (Authelia file backend) and pre-creates them in downstream apps (e.g.
// Planka) so they can be referenced before their first login. See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/uppertoe/vps-user-portal/internal/audit"
	"github.com/uppertoe/vps-user-portal/internal/config"
	"github.com/uppertoe/vps-user-portal/internal/email"
	"github.com/uppertoe/vps-user-portal/internal/provision"
	_ "github.com/uppertoe/vps-user-portal/internal/provision/planka" // register planka-postgres
	"github.com/uppertoe/vps-user-portal/internal/server"
	"github.com/uppertoe/vps-user-portal/internal/userstore"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz and exit (for the container HEALTHCHECK)")
	flag.Parse()

	if *healthcheck {
		os.Exit(probe())
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration invalid", "err", err)
		os.Exit(1)
	}

	store := userstore.New(cfg.UsersFile)
	if _, err := store.List(); err != nil {
		slog.Error("users file unreadable — is the Authelia users directory mounted?", "path", cfg.UsersFile, "err", err)
		os.Exit(1)
	}

	provs, err := provision.Load(cfg.ProvisionersFile)
	if err != nil {
		slog.Error("provisioners config invalid", "err", err)
		os.Exit(1)
	}

	var mail email.Sender
	switch cfg.EmailBackend {
	case "smtp":
		mail = &email.SMTP{
			Host: cfg.EmailHost, Port: cfg.EmailPort,
			Username: cfg.EmailUsername, Password: cfg.EmailPassword,
			From: cfg.EmailFrom, SubjectPrefix: cfg.EmailSubjectPrefix,
		}
	case "log":
		mail = email.Log{}
	default:
		mail = email.None{}
	}

	srv := server.New(cfg, store, provs, mail, &audit.Logger{NtfyURL: cfg.NtfyURL})

	// Fail fast if a provisioner's assumptions don't hold (e.g. Planka schema
	// drift): a crash-looping container is a loud, safe failure mode.
	ctx := context.Background()
	if err := srv.RunChecks(ctx); err != nil {
		slog.Error("startup provisioner check failed", "err", err)
		os.Exit(1)
	}
	go srv.CheckLoop(ctx, 5*time.Minute)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	slog.Info("listening", "addr", cfg.ListenAddr, "provisioners", len(provs))
	if err := httpSrv.ListenAndServe(); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func probe() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", resp.Status)
		return 1
	}
	return 0
}
