// Package server is the portal's HTTP layer.
//
// Trust model: the portal listens only on a private proxy network behind
// Caddy's `import protected_admin` guard, which 302s anyone who isn't a
// signed-in (email-OTP + TOTP) admin before a byte reaches us, strips
// client-supplied Remote-* headers and injects authoritative ones. The
// requireAdmin middleware re-checks Remote-Groups anyway (defence in depth):
// if the portal is ever miswired onto a network something else can reach,
// requests carry no trusted headers and are refused.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-user-portal/internal/audit"
	"github.com/uppertoe/vps-user-portal/internal/config"
	"github.com/uppertoe/vps-user-portal/internal/email"
	"github.com/uppertoe/vps-user-portal/internal/provision"
	"github.com/uppertoe/vps-user-portal/internal/userstore"
)

type Server struct {
	cfg   *config.Config
	store *userstore.Store
	provs []provision.Provisioner
	mail  email.Sender
	audit *audit.Logger

	mu       sync.RWMutex
	checkErr error // last provisioner Check() failure; nil = healthy
	now      func() time.Time
}

func New(cfg *config.Config, store *userstore.Store, provs []provision.Provisioner, mail email.Sender, aud *audit.Logger) *Server {
	return &Server{cfg: cfg, store: store, provs: provs, mail: mail, audit: aud, now: time.Now}
}

// RunChecks runs every provisioner's Check and records the result for
// /healthz. Call at startup (fail fast) and periodically.
func (s *Server) RunChecks(ctx context.Context) error {
	var firstErr error
	for _, p := range s.provs {
		if err := p.Check(ctx); err != nil {
			err = fmt.Errorf("provisioner %s: %w", p.Name(), err)
			slog.Error("provisioner check failed", "provisioner", p.Name(), "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	s.mu.Lock()
	s.checkErr = firstErr
	s.mu.Unlock()
	return firstErr
}

// CheckLoop re-runs RunChecks every interval until ctx ends, so schema drift
// after a Planka upgrade flips /healthz without a portal restart.
func (s *Server) CheckLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.RunChecks(ctx)
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /static/style.css", http.HandlerFunc(handleCSS))

	mux.Handle("GET /{$}", s.requireAdmin(s.handleList))
	mux.Handle("GET /invite", s.requireAdmin(s.handleInviteForm))
	mux.Handle("POST /invite", s.requireAdmin(s.handleInvite))
	mux.Handle("GET /users/{username}", s.requireAdmin(s.handleUser))
	mux.Handle("POST /users/{username}/groups", s.requireAdmin(s.handleSetGroups))
	mux.Handle("POST /users/{username}/delete", s.requireAdmin(s.handleDelete))

	return securityHeaders(mux)
}

// maxBodyBytes caps request bodies: the forms here are tiny, so a small limit
// removes an unbounded-ParseForm memory-exhaustion vector on a small VPS.
const maxBodyBytes = 64 << 10

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "private, no-cache")
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// --- identity ---

type identity struct {
	User   string
	Email  string
	Groups []string
}

type ctxKey struct{}

func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proof-of-Caddy: if a shared secret is configured, require it before
		// trusting ANY Remote-* header. Caddy injects X-Portal-Auth on the
		// reverse_proxy; a co-tenant of the portal's networks (e.g. a
		// compromised planka-db reaching us directly, bypassing Caddy) can't
		// supply it, so it can't forge Remote-Groups: admin. Constant-time.
		if s.cfg.SharedSecret != "" {
			got := r.Header.Get("X-Portal-Auth")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.SharedSecret)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		id := identity{
			User:   strings.TrimSpace(r.Header.Get("Remote-User")),
			Email:  strings.TrimSpace(r.Header.Get("Remote-Email")),
			Groups: splitGroups(r.Header.Get("Remote-Groups")),
		}
		isAdmin := false
		for _, g := range id.Groups {
			if g == s.cfg.AdminGroup {
				isAdmin = true
				break
			}
		}
		if id.User == "" || !isAdmin {
			// Behind the gateway this should be unreachable; reaching it
			// means misconfiguration, so say exactly that.
			http.Error(w, "forbidden: this service must sit behind the forward-auth admin guard", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func actor(r *http.Request) identity {
	id, _ := r.Context().Value(ctxKey{}).(identity)
	return id
}

func splitGroups(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if csrfValid(s.cfg.CSRFSecret, actor(r).User, r.PostFormValue("csrf"), s.now()) {
		return true
	}
	http.Error(w, "invalid or expired form token — go back, reload the page and retry", http.StatusForbidden)
	return false
}

// --- health ---

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	err := s.checkErr
	s.mu.RUnlock()
	if err != nil {
		// /healthz is the one UNAUTHENTICATED endpoint. Keep the detail (which
		// can carry the DB host/port/role from a pgx error) in the log only;
		// the client gets a bare status.
		slog.Warn("healthz reporting unhealthy", "err", err)
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// --- pages ---

type userRow struct {
	userstore.User
	Apps map[string]provision.AppStatus // provisioner name -> status
}

// appStatusRow is one app's status on the user-detail page, carrying the
// friendly DisplayName (not the raw provisioner name) for display.
type appStatusRow struct {
	DisplayName string
	Status      provision.AppStatus
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.List()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	emails := make([]string, len(users))
	for i, u := range users {
		emails[i] = strings.ToLower(u.Email)
	}
	rows := make([]userRow, len(users))
	var warnings []string
	for i, u := range users {
		rows[i] = userRow{User: u, Apps: map[string]provision.AppStatus{}}
	}
	for _, p := range s.provs {
		statuses, err := p.Status(r.Context(), emails)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s status unavailable: %v", p.Name(), err))
			continue
		}
		for i, u := range users {
			rows[i].Apps[p.Name()] = statuses[strings.ToLower(u.Email)]
		}
	}
	s.render(w, r, "list.html", map[string]any{
		"Rows":     rows,
		"Apps":     s.provisionerNames(),
		"AppInfos": s.appInfos(),
		"Warnings": warnings,
	})
}

func (s *Server) handleInviteForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "invite.html", map[string]any{
		"Groups":   s.cfg.GroupOptions(),
		"Domains":  s.cfg.AllowedEmailDomains,
		"Selected": map[string]bool{},
	})
}

// inviteEntry is one parsed line of the batch form: "email" or "email, Name".
type inviteEntry struct {
	Email       string
	DisplayName string
}

// inviteResult is one row's outcome, shown in the batch summary.
type inviteResult struct {
	Email  string
	Status string // "created" | "skipped" | "failed"
	Detail string // reason (skipped/failed) or non-fatal warnings (created)
}

// handleInvite processes the batch invite form: one user per line, one set of
// groups for the whole batch, and an OFF-by-default welcome email. Accounts are
// created immediately (assignable in Planka before first login); a per-row
// failure never rolls back earlier rows.
func (s *Server) handleInvite(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	adm := actor(r)
	groups := s.selectedGroups(r)
	sendEmail := r.PostFormValue("send_email") == "on"
	rawUsers := r.PostFormValue("users")
	entries := parseInviteLines(rawUsers)

	reshow := func(msg string) {
		s.render(w, r, "invite.html", map[string]any{
			"Groups": s.cfg.GroupOptions(), "Domains": s.cfg.AllowedEmailDomains,
			"Error": msg, "Users": rawUsers, "Selected": toSet(groups), "SendEmail": sendEmail,
		})
	}
	if len(groups) == 0 {
		reshow("Select at least one access level to grant.")
		return
	}
	if len(entries) == 0 {
		reshow("Enter at least one email address (one per line).")
		return
	}

	var results []inviteResult
	created := 0
	for _, e := range entries {
		u, err := s.buildInviteUser(e.Email, e.DisplayName, groups)
		if err != nil {
			results = append(results, inviteResult{e.Email, "failed", err.Error()})
			continue
		}
		hash, herr := userstore.ThrowawayHash()
		if herr != nil {
			s.audit.Event(adm.User, "invite", u.Email, "", herr)
			results = append(results, inviteResult{e.Email, "failed", "internal error creating the account"})
			continue
		}
		// SSO store write FIRST: if a provisioner then fails the invite
		// self-heals at first login; the reverse would orphan app rows.
		if err := s.store.Add(u, hash); err != nil {
			if errors.Is(err, userstore.ErrDuplicate) {
				results = append(results, inviteResult{e.Email, "skipped", "already exists"})
			} else {
				s.audit.Event(adm.User, "invite", u.Email, "", err)
				results = append(results, inviteResult{e.Email, "failed", "could not write the user store"})
			}
			continue
		}
		var warns []string
		pu := provision.User{Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Groups: u.Groups}
		for _, p := range s.provs {
			if err := p.Provision(r.Context(), pu); err != nil {
				warns = append(warns, fmt.Sprintf("%s: %v (will self-heal at first login)", p.Name(), err))
			}
		}
		if sendEmail {
			if err := s.mail.SendWelcome(u.Email, u.DisplayName, s.cfg.SSOURL); err != nil {
				warns = append(warns, "welcome email failed: "+err.Error())
			}
		}
		created++
		s.audit.Event(adm.User, "invite", u.Email,
			fmt.Sprintf("username=%s groups=%s email=%t warnings=%d", u.Username, strings.Join(groups, " "), sendEmail, len(warns)), nil)
		results = append(results, inviteResult{e.Email, "created", strings.Join(warns, "; ")})
	}

	s.render(w, r, "invite-result.html", map[string]any{
		"Results":   results,
		"Created":   created,
		"Total":     len(entries),
		"SendEmail": sendEmail,
		"SSOURL":    s.cfg.SSOURL,
	})
}

// parseInviteLines turns the textarea into entries: one per non-blank line,
// "email" or "email, Display Name". Emails are lowercased; duplicates within
// the paste are collapsed (so the same address isn't created-then-skipped).
func parseInviteLines(raw string) []inviteEntry {
	var out []inviteEntry
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		emailPart, namePart, _ := strings.Cut(line, ",")
		addr := strings.ToLower(strings.TrimSpace(emailPart))
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, inviteEntry{Email: addr, DisplayName: strings.TrimSpace(namePart)})
	}
	return out
}

// buildInviteUser validates one entry and derives the username (and display
// name, if omitted). Groups are validated once by the caller.
func (s *Server) buildInviteUser(emailAddr, displayName string, groups []string) (userstore.User, error) {
	local, domain, ok := strings.Cut(emailAddr, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(emailAddr, " \t\r\n") {
		return userstore.User{}, fmt.Errorf("not a valid email address")
	}
	allowed := false
	for _, d := range s.cfg.AllowedEmailDomains {
		if domain == d {
			allowed = true
			break
		}
	}
	if !allowed {
		return userstore.User{}, fmt.Errorf("domain @%s is not on the allowlist", domain)
	}
	if displayName == "" {
		displayName = deriveDisplayName(local)
	}
	if len(displayName) > 100 {
		return userstore.User{}, fmt.Errorf("display name is too long (max 100 characters)")
	}
	username := userstore.DeriveUsername(emailAddr)
	if !userstore.ValidUsername(username) {
		return userstore.User{}, fmt.Errorf("could not derive a valid username from the email")
	}
	return userstore.User{Username: username, DisplayName: displayName, Email: emailAddr, Groups: groups}, nil
}

// deriveDisplayName turns an email local-part into a readable name:
// "jane.smith" -> "Jane Smith". A best-effort default the admin can edit later.
func deriveDisplayName(local string) string {
	fields := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' })
	for i, f := range fields {
		if f != "" {
			fields[i] = strings.ToUpper(f[:1]) + f[1:]
		}
	}
	name := strings.Join(fields, " ")
	if name == "" {
		return local
	}
	return name
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.Get(r.PathValue("username"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var apps []appStatusRow
	for _, p := range s.provs {
		st, err := p.Status(r.Context(), []string{strings.ToLower(u.Email)})
		if err == nil {
			apps = append(apps, appStatusRow{DisplayName: p.Info().DisplayName, Status: st[strings.ToLower(u.Email)]})
		}
	}
	s.render(w, r, "user.html", map[string]any{
		"U": u, "Groups": s.cfg.GroupOptions(), "Selected": toSet(u.Groups), "Apps": apps,
	})
}

func (s *Server) handleSetGroups(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	adm := actor(r)
	username := r.PathValue("username")
	groups := s.selectedGroups(r)
	if err := s.store.SetGroups(username, groups); err != nil {
		s.audit.Event(adm.User, "set-access", username, "groups="+strings.Join(groups, " "), err)
		s.fail(w, r, err)
		return
	}
	// Push the new access into connected apps NOW (update role / reactivate /
	// deactivate) so an edit takes effect immediately rather than only at the
	// user's next login. Non-fatal: a failure just defers to next login.
	var warnings []string
	if u, err := s.store.Get(username); err == nil {
		pu := provision.User{Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Groups: u.Groups}
		for _, p := range s.provs {
			if err := p.Sync(r.Context(), pu); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: couldn't apply the change immediately: %v (it will apply at the user's next login)", p.Name(), err))
			}
		}
	}
	s.audit.Event(adm.User, "set-access", username, fmt.Sprintf("groups=%s warnings=%d", strings.Join(groups, " "), len(warnings)), nil)
	if len(warnings) > 0 {
		s.render(w, r, "message.html", map[string]any{
			"Title":    "Access updated",
			"Message":  fmt.Sprintf("Access for %s was saved.", username),
			"Warnings": warnings,
		})
		return
	}
	http.Redirect(w, r, "/users/"+username, http.StatusSeeOther)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	adm := actor(r)
	username := r.PathValue("username")
	if r.PostFormValue("confirm") != "on" {
		http.Error(w, "confirmation checkbox required", http.StatusBadRequest)
		return
	}
	u, err := s.store.Get(username)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Severing SSO comes first — it is the security-critical step (with SSO
	// enforced there is no other way in). App-side deactivation follows;
	// a failure there leaves an inert app account and a loud warning.
	if err := s.store.Delete(username); err != nil {
		s.audit.Event(adm.User, "delete", u.Email, "", err)
		s.fail(w, r, err)
		return
	}
	var warnings []string
	pu := provision.User{Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Groups: u.Groups}
	for _, p := range s.provs {
		if err := p.Deprovision(r.Context(), pu); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: deactivation failed: %v — deactivate manually in the app", p.Name(), err))
		}
	}
	s.audit.Event(adm.User, "delete", u.Email, fmt.Sprintf("username=%s warnings=%d", username, len(warnings)), nil)
	s.render(w, r, "message.html", map[string]any{
		"Title":    "User removed",
		"Message":  fmt.Sprintf("%s can no longer sign in. Existing sessions expire within the hour; restart Authelia to revoke immediately.", u.Email),
		"Warnings": warnings,
	})
}

// --- helpers ---

// selectedGroups returns the posted groups, filtered to the configured set —
// a client cannot smuggle an unknown group name into the users file.
func (s *Server) selectedGroups(r *http.Request) []string {
	_ = r.ParseForm()
	allowed := toSet(s.cfg.Groups)
	var out []string
	for _, g := range r.PostForm["groups"] {
		if allowed[g] {
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func (s *Server) provisionerNames() []string {
	names := make([]string, len(s.provs))
	for i, p := range s.provs {
		names[i] = p.Name()
	}
	return names
}

func (s *Server) appInfos() []provision.AppInfo {
	out := make([]provision.AppInfo, len(s.provs))
	for i, p := range s.provs {
		out[i] = p.Info()
	}
	return out
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "path", r.URL.Path, "err", err)
	s.render(w, r, "message.html", map[string]any{
		"Title": "Something went wrong", "Error": err.Error(),
	})
}
