package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-user-portal/internal/audit"
	"github.com/uppertoe/vps-user-portal/internal/config"
	"github.com/uppertoe/vps-user-portal/internal/email"
	"github.com/uppertoe/vps-user-portal/internal/provision"
	"github.com/uppertoe/vps-user-portal/internal/userstore"
)

const usersSeed = `users:
  alice:
    displayname: Alice Example
    email: alice@example.org
    password: "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    groups:
      - planka-admins
`

// stubProvisioner records calls and can be told to fail.
type stubProvisioner struct {
	provisioned  []provision.User
	synced       []provision.User
	deprovisiond []provision.User
	failNext     bool
}

func (s *stubProvisioner) Name() string { return "stubapp" }
func (s *stubProvisioner) Info() provision.AppInfo {
	return provision.AppInfo{Name: "stubapp", DisplayName: "Stub App", URL: "https://stub.example.org"}
}
func (s *stubProvisioner) Check(context.Context) error { return nil }
func (s *stubProvisioner) Provision(_ context.Context, u provision.User) error {
	if s.failNext {
		s.failNext = false
		return context.DeadlineExceeded
	}
	s.provisioned = append(s.provisioned, u)
	return nil
}
func (s *stubProvisioner) Sync(_ context.Context, u provision.User) error {
	s.synced = append(s.synced, u)
	return nil
}
func (s *stubProvisioner) Deprovision(_ context.Context, u provision.User) error {
	s.deprovisiond = append(s.deprovisiond, u)
	return nil
}
func (s *stubProvisioner) Status(_ context.Context, emails []string) (map[string]provision.AppStatus, error) {
	out := map[string]provision.AppStatus{}
	for _, u := range s.provisioned {
		out[strings.ToLower(u.Email)] = provision.AppStatus{Present: true, Role: "boardUser"}
	}
	return out, nil
}

func newTestServer(t *testing.T) (*Server, *stubProvisioner, *userstore.Store) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users_database.yml")
	if err := os.WriteFile(path, []byte(usersSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		UsersFile:           path,
		AllowedEmailDomains: []string{"example.org"},
		Groups:              []string{"planka-users", "planka-owners", "planka-admins"},
		AdminGroup:          "admin",
		CSRFSecret:          []byte("0123456789abcdef0123456789abcdef"),
		SSOURL:              "https://sso.example.org",
	}
	stub := &stubProvisioner{}
	store := userstore.New(path)
	srv := New(cfg, store, []provision.Provisioner{stub}, email.None{}, &audit.Logger{})
	return srv, stub, store
}

func asAdmin(req *http.Request) *http.Request {
	req.Header.Set("Remote-User", "admin@example.org")
	req.Header.Set("Remote-Email", "admin@example.org")
	req.Header.Set("Remote-Groups", "admin,user")
	return req
}

func do(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSharedSecretGate(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.SharedSecret = "s3cret-proof-of-caddy"

	// Valid admin identity but NO X-Portal-Auth (as a co-tenant reaching the
	// portal directly, bypassing Caddy) -> refused before Remote-* is trusted.
	if rec := do(srv, asAdmin(httptest.NewRequest("GET", "/", nil))); rec.Code != http.StatusForbidden {
		t.Errorf("missing shared secret: want 403, got %d", rec.Code)
	}
	// Wrong secret -> refused.
	req := asAdmin(httptest.NewRequest("GET", "/", nil))
	req.Header.Set("X-Portal-Auth", "wrong")
	if rec := do(srv, req); rec.Code != http.StatusForbidden {
		t.Errorf("wrong shared secret: want 403, got %d", rec.Code)
	}
	// Correct secret (what Caddy injects) -> allowed through.
	req = asAdmin(httptest.NewRequest("GET", "/", nil))
	req.Header.Set("X-Portal-Auth", "s3cret-proof-of-caddy")
	if rec := do(srv, req); rec.Code != http.StatusOK {
		t.Errorf("correct shared secret: want 200, got %d", rec.Code)
	}
}

func TestRefusesWithoutAdminIdentity(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, tc := range []struct {
		name string
		mod  func(*http.Request)
	}{
		{"no headers", func(*http.Request) {}},
		{"non-admin group", func(r *http.Request) {
			r.Header.Set("Remote-User", "bob@example.org")
			r.Header.Set("Remote-Groups", "user")
		}},
		{"admin substring but not group", func(r *http.Request) {
			r.Header.Set("Remote-User", "bob@example.org")
			r.Header.Set("Remote-Groups", "administrators")
		}},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		tc.mod(req)
		if rec := do(srv, req); rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", tc.name, rec.Code)
		}
	}
}

func TestHealthzNeedsNoIdentity(t *testing.T) {
	srv, _, _ := newTestServer(t)
	if rec := do(srv, httptest.NewRequest("GET", "/healthz", nil)); rec.Code != http.StatusOK {
		t.Errorf("healthz: got %d, want 200", rec.Code)
	}
}

func TestListShowsUsers(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := do(srv, asAdmin(httptest.NewRequest("GET", "/", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "alice@example.org") {
		t.Error("list page missing seeded user")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("weak or missing CSP: %q", csp)
	}
}

func TestInviteFormRendersCompletely(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := do(srv, asAdmin(httptest.NewRequest("GET", "/invite", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	// A render error truncates the page; the submit button is last, so its
	// presence proves the template executed to the end.
	if !strings.Contains(body, "Create accounts") {
		t.Error("invite form truncated (template render error?)")
	}
	for _, g := range srv.cfg.Groups {
		if !strings.Contains(body, `value="`+g+`"`) {
			t.Errorf("group checkbox %q missing", g)
		}
	}
}

// recordingMail records SendWelcome calls so tests can assert email is off by
// default and sent only when opted in.
type recordingMail struct{ sent []string }

func (m *recordingMail) SendWelcome(to, _, _ string) error { m.sent = append(m.sent, to); return nil }

func inviteForm(srv *Server, form url.Values) *http.Request {
	if form.Get("csrf") == "" {
		form.Set("csrf", csrfToken(srv.cfg.CSRFSecret, "admin@example.org", time.Now()))
	}
	req := httptest.NewRequest("POST", "/invite", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return asAdmin(req)
}

func TestInviteFlow(t *testing.T) {
	srv, stub, store := newTestServer(t)
	rec := do(srv, inviteForm(srv, url.Values{
		"users":  {"Carol@example.org, Carol New"},
		"groups": {"planka-users"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	u, err := store.Get("carol")
	if err != nil {
		t.Fatalf("carol not in users file: %v", err)
	}
	if u.Email != "carol@example.org" || u.DisplayName != "Carol New" || u.Groups[0] != "planka-users" {
		t.Errorf("unexpected stored user: %+v", u)
	}
	if len(stub.provisioned) != 1 || stub.provisioned[0].Email != "carol@example.org" {
		t.Errorf("provisioner not called correctly: %+v", stub.provisioned)
	}
}

// A batch: valid rows are created, a bad-domain row fails, a duplicate is
// skipped — and one bad row never rolls back the good ones.
func TestInviteBatch(t *testing.T) {
	srv, stub, store := newTestServer(t)
	mail := &recordingMail{}
	srv.mail = mail
	rec := do(srv, inviteForm(srv, url.Values{
		// derived name, explicit name, bad domain (fails), duplicate seed (skipped)
		"users":  {"jane.smith@example.org\nbob@example.org, Bob Jones\nx@evil.org\nalice@example.org"},
		"groups": {"planka-users"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	// jane + bob created; alice (dup) and x@evil.org not added → seed + 2 = 3.
	if users, _ := store.List(); len(users) != 3 {
		t.Fatalf("want 3 users after batch, got %d", len(users))
	}
	jane, err := store.Get("jane.smith")
	if err != nil || jane.DisplayName != "Jane Smith" { // derived from the local-part
		t.Errorf("derived display name wrong: %+v (%v)", jane, err)
	}
	if len(stub.provisioned) != 2 {
		t.Errorf("want 2 provisioned (the created ones), got %d", len(stub.provisioned))
	}
	// Email is OFF by default: no send_email field posted.
	if len(mail.sent) != 0 {
		t.Errorf("no welcome email should be sent by default, sent %v", mail.sent)
	}
}

func TestInviteSendsEmailOnlyWhenOptedIn(t *testing.T) {
	srv, _, _ := newTestServer(t)
	mail := &recordingMail{}
	srv.mail = mail
	do(srv, inviteForm(srv, url.Values{
		"users":      {"dan@example.org"},
		"groups":     {"planka-users"},
		"send_email": {"on"},
	}))
	if len(mail.sent) != 1 || mail.sent[0] != "dan@example.org" {
		t.Errorf("opted-in email not sent: %v", mail.sent)
	}
}

func TestInviteRejections(t *testing.T) {
	srv, stub, store := newTestServer(t)
	// Batch-level errors re-show the form and create nothing.
	for name, form := range map[string]url.Values{
		"no groups":     {"users": {"x@example.org"}},
		"unknown group": {"users": {"x@example.org"}, "groups": {"sneaky-admins"}},
		"empty users":   {"users": {"   \n  "}, "groups": {"planka-users"}},
	} {
		do(srv, inviteForm(srv, form))
		if users, _ := store.List(); len(users) != 1 {
			t.Fatalf("%s: user was created", name)
		}
	}
	// A bad-domain row is reported as failed, not created.
	do(srv, inviteForm(srv, url.Values{"users": {"x@evil.org"}, "groups": {"planka-users"}}))
	if users, _ := store.List(); len(users) != 1 {
		t.Fatal("bad-domain row created a user")
	}
	if len(stub.provisioned) != 0 {
		t.Error("provisioner called for a rejected invite")
	}
}

func TestInviteRequiresValidCSRF(t *testing.T) {
	srv, _, store := newTestServer(t)
	rec := do(srv, inviteForm(srv, url.Values{
		"users":  {"x@example.org"},
		"groups": {"planka-users"},
		"csrf":   {"1.bogus"},
	}))
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad csrf: got %d, want 403", rec.Code)
	}
	if users, _ := store.List(); len(users) != 1 {
		t.Error("user created despite bad CSRF token")
	}
}

func TestProvisionerFailureIsNonFatal(t *testing.T) {
	srv, stub, store := newTestServer(t)
	stub.failNext = true
	rec := do(srv, inviteForm(srv, url.Values{
		"users":  {"dave@example.org, Dave"},
		"groups": {"planka-users"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "self-heal") {
		t.Error("provisioner warning not surfaced to the admin")
	}
	if _, err := store.Get("dave"); err != nil {
		t.Error("SSO user should exist even when app provisioning fails")
	}
}

func TestDeleteFlow(t *testing.T) {
	srv, stub, store := newTestServer(t)
	form := url.Values{
		"confirm": {"on"},
		"csrf":    {csrfToken(srv.cfg.CSRFSecret, "admin@example.org", time.Now())},
	}
	req := httptest.NewRequest("POST", "/users/alice/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := do(srv, asAdmin(req))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if users, _ := store.List(); len(users) != 0 {
		t.Error("alice still present after delete")
	}
	if len(stub.deprovisiond) != 1 || stub.deprovisiond[0].Email != "alice@example.org" {
		t.Errorf("deprovision not called: %+v", stub.deprovisiond)
	}
}

func TestDeleteRequiresConfirmation(t *testing.T) {
	srv, _, store := newTestServer(t)
	form := url.Values{"csrf": {csrfToken(srv.cfg.CSRFSecret, "admin@example.org", time.Now())}}
	req := httptest.NewRequest("POST", "/users/alice/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := do(srv, asAdmin(req)); rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rec.Code)
	}
	if users, _ := store.List(); len(users) != 1 {
		t.Error("user deleted without confirmation")
	}
}

func TestSetGroups(t *testing.T) {
	srv, stub, store := newTestServer(t)
	form := url.Values{
		"groups": {"planka-owners"},
		"csrf":   {csrfToken(srv.cfg.CSRFSecret, "admin@example.org", time.Now())},
	}
	req := httptest.NewRequest("POST", "/users/alice/groups", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := do(srv, asAdmin(req)); rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	u, _ := store.Get("alice")
	if len(u.Groups) != 1 || u.Groups[0] != "planka-owners" {
		t.Errorf("groups not updated: %v", u.Groups)
	}
	// Editing access must Sync connected apps immediately (not wait for login).
	if len(stub.synced) != 1 || stub.synced[0].Email != "alice@example.org" {
		t.Errorf("provisioner Sync not called on access edit: %+v", stub.synced)
	}
	if stub.synced[0].Groups[0] != "planka-owners" {
		t.Errorf("Sync got stale groups: %v", stub.synced[0].Groups)
	}
}
