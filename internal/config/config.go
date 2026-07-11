// Package config parses the portal's environment-only configuration.
//
// The portal is deliberately stateless: everything it needs arrives via
// environment variables (secrets from a mode-600 .env on the host) plus an
// optional provisioners.yaml for app integrations.
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	// ListenAddr is the HTTP bind address, e.g. ":8080".
	ListenAddr string
	// UsersFile is the path to Authelia's users_database.yml. Its parent
	// directory must be writable (atomic temp+rename writes) and shared with
	// the Authelia container, which watches it for changes.
	UsersFile string
	// ProvisionersFile optionally points at a provisioners.yaml describing
	// app integrations (e.g. planka-postgres). Empty = Authelia-only mode.
	ProvisionersFile string
	// AllowedEmailDomains is the invite allowlist (lowercase, no @).
	AllowedEmailDomains []string
	// Groups are the group names offered as checkboxes on the invite form.
	Groups []string
	// AdminGroup is the Remote-Groups entry required on every request
	// (defence in depth behind Caddy's protected_admin gate).
	AdminGroup string
	// CSRFSecret keys the HMAC CSRF tokens. Required, >= 32 bytes.
	CSRFSecret []byte
	// SSOURL is the Authelia portal URL shown in welcome emails and the UI,
	// e.g. https://sso.example.org.
	SSOURL string
	// Email delivery for welcome mail: "smtp", "log" (print to stdout, for
	// local testing) or "none".
	EmailBackend  string
	EmailHost     string
	EmailPort     string
	EmailUsername string
	EmailPassword string
	EmailFrom     string
	// EmailSubjectPrefix brands the welcome mail subject, e.g. "[RCH Anaesthesia]".
	EmailSubjectPrefix string
	// NtfyURL optionally receives a notification for every mutation, e.g.
	// https://ntfy.example.org/user-portal. Empty = disabled.
	NtfyURL string
}

func get(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// splitList splits a comma- and/or space-separated list.
func splitList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:          get("LISTEN_ADDR", ":8080"),
		UsersFile:           get("USERS_FILE", "/authelia-users/users_database.yml"),
		ProvisionersFile:    get("PROVISIONERS_FILE", ""),
		AllowedEmailDomains: splitList(strings.ToLower(get("ALLOWED_EMAIL_DOMAINS", ""))),
		Groups:              splitList(get("GROUPS", "")),
		AdminGroup:          get("ADMIN_GROUP", "admin"),
		SSOURL:              strings.TrimRight(get("SSO_URL", ""), "/"),
		EmailBackend:        get("EMAIL_BACKEND", "none"),
		EmailHost:           get("EMAIL_HOST", ""),
		EmailPort:           get("EMAIL_PORT", "587"),
		EmailUsername:       get("EMAIL_USERNAME", ""),
		EmailPassword:       os.Getenv("EMAIL_PASSWORD"),
		EmailFrom:           get("EMAIL_FROM", ""),
		EmailSubjectPrefix:  get("EMAIL_SUBJECT_PREFIX", "[User portal]"),
		NtfyURL:             get("NTFY_URL", ""),
	}

	secret := strings.TrimSpace(os.Getenv("CSRF_SECRET"))
	if len(secret) < 32 {
		return nil, fmt.Errorf("CSRF_SECRET must be set to at least 32 characters (openssl rand -hex 32)")
	}
	c.CSRFSecret = []byte(secret)

	if len(c.AllowedEmailDomains) == 0 {
		return nil, fmt.Errorf("ALLOWED_EMAIL_DOMAINS must list at least one domain")
	}
	if len(c.Groups) == 0 {
		return nil, fmt.Errorf("GROUPS must list at least one assignable group")
	}
	if c.SSOURL == "" || !strings.HasPrefix(c.SSOURL, "https://") {
		return nil, fmt.Errorf("SSO_URL must be an https:// URL to the Authelia portal")
	}
	switch c.EmailBackend {
	case "smtp":
		if c.EmailHost == "" || c.EmailFrom == "" {
			return nil, fmt.Errorf("EMAIL_BACKEND=smtp requires EMAIL_HOST and EMAIL_FROM")
		}
	case "log", "none":
	default:
		return nil, fmt.Errorf("EMAIL_BACKEND must be smtp, log or none (got %q)", c.EmailBackend)
	}
	return c, nil
}
