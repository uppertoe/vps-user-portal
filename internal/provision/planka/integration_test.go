//go:build integration

// Integration tests that run against a REAL Planka Postgres (schema created by
// Planka's own migrations), not a mock. This is what catches "my INSERT
// doesn't match the live schema" bugs that unit tests structurally cannot.
//
// Run against the e2e harness:
//
//	PLANKA_TEST_DSN=postgres://planka:planka@127.0.0.1:55433/planka \
//	  go test -tags integration ./internal/provision/planka/ -run Integration -v
package planka

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uppertoe/vps-user-portal/internal/provision"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PLANKA_TEST_DSN")
	if dsn == "" {
		t.Skip("PLANKA_TEST_DSN not set; skipping live Planka integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testProvisioner(t *testing.T, pool *pgxpool.Pool) *Provisioner {
	return &Provisioner{
		name: "planka",
		pool: pool,
		roles: []roleRule{
			{"planka-admins", "admin"},
			{"planka-owners", "projectOwner"},
			{"planka-users", "boardUser"},
		},
	}
}

// fullInviteGrants is the exact least-privilege grant set the README/docs
// prescribe (column-scoped SELECT, no table-wide read of password/PII). Each
// entry omits the trailing "TO <role>" — makeInviteRole appends the per-test
// role name.
var fullInviteGrants = []string{
	`GRANT SELECT (email, role, is_deactivated) ON user_account`,
	`GRANT INSERT ON user_account`,
	`GRANT UPDATE (is_deactivated, role) ON user_account`,
	`GRANT USAGE ON SEQUENCE next_id_seq`,
}

// makeInviteRole creates a non-superuser role (named per-test, so parallel or
// sequential tests never collide) with exactly the given GRANTs and returns a
// pool connected as it plus the role name. Check() now rejects a superuser, and
// the harness DSN is the Planka owner (superuser) — so the privilege probe must
// be exercised as the real narrow role, not the owner.
func makeInviteRole(t *testing.T, admin *pgxpool.Pool, grants []string) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	var db string
	if err := admin.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatalf("current_database: %v", err)
	}
	role := strings.ToLower("ip_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	drop := func() {
		for _, q := range []string{
			`REVOKE ALL ON user_account FROM ` + role,
			`REVOKE ALL ON SCHEMA public FROM ` + role,
			`REVOKE ALL ON DATABASE "` + db + `" FROM ` + role,
			`DROP ROLE IF EXISTS ` + role,
		} {
			_, _ = admin.Exec(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	setup := []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'probe_pw_x9'`,
		`GRANT CONNECT ON DATABASE "` + db + `" TO ` + role,
		`GRANT USAGE ON SCHEMA public TO ` + role,
	}
	for _, g := range grants {
		setup = append(setup, g+" TO "+role)
	}
	for _, q := range setup {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatalf("setup %q: %v", q, err)
		}
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "probe_pw_x9"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(p.Close)
	return p, role
}

// The prescribed least-privilege grants (column-scoped SELECT included) pass
// Check against the real schema — the columns the probe reads are exactly those
// granted.
func TestIntegrationCheckPassesWithLeastPrivilegeGrants(t *testing.T) {
	admin := testPool(t)
	pool, _ := makeInviteRole(t, admin, fullInviteGrants)
	p := testProvisioner(t, pool)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Check() failed with the prescribed least-privilege grants: %v", err)
	}
}

// A DSN pointed at the Planka owner (superuser) must be rejected — least
// privilege is otherwise entirely operator-enforced.
func TestIntegrationCheckRejectsSuperuser(t *testing.T) {
	p := testProvisioner(t, testPool(t)) // testPool connects as the superuser owner
	err := p.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SUPERUSER") {
		t.Fatalf("want a superuser-rejection error, got %v", err)
	}
}

func TestIntegrationProvisionInsertsRealRow(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	p := testProvisioner(t, pool)

	email := "int-test-carol@example.org"
	_, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email) })

	u := provision.User{Username: "inttestcarol", DisplayName: "Carol Int", Email: "Int-Test-Carol@example.org", Groups: []string{"planka-users"}}
	if err := p.Provision(ctx, u); err != nil {
		t.Fatalf("Provision against real schema failed: %v", err)
	}

	// Row is exactly the SSO-linkable shape: correct role, is_sso_user, NULL password.
	var role string
	var isSSO, deactivated bool
	var password *string
	err := pool.QueryRow(ctx,
		`SELECT role, is_sso_user, is_deactivated, password FROM user_account WHERE lower(email)=$1`,
		email).Scan(&role, &isSSO, &deactivated, &password)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if role != "boardUser" || !isSSO || deactivated || password != nil {
		t.Errorf("unexpected row: role=%q isSSO=%v deact=%v passwordNil=%v", role, isSSO, deactivated, password == nil)
	}

	// Status sees it; Deprovision deactivates without deleting.
	st, err := p.Status(ctx, []string{email})
	if err != nil || !st[email].Present || st[email].Deactivated {
		t.Errorf("Status wrong: %+v err=%v", st[email], err)
	}
	if err := p.Deprovision(ctx, u); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	st, _ = p.Status(ctx, []string{email})
	if !st[email].Present || !st[email].Deactivated {
		t.Errorf("after Deprovision want present+deactivated, got %+v", st[email])
	}
}

func TestIntegrationSyncUpdatesRoleAndReactivation(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	p := testProvisioner(t, pool)
	email := "int-test-sync@example.org"
	_, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email) })

	u := provision.User{Username: "inttestsync", DisplayName: "Sync", Email: email, Groups: []string{"planka-users"}}
	if err := p.Provision(ctx, u); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Promote boardUser -> projectOwner: Sync must update the live row now.
	u.Groups = []string{"planka-owners"}
	if err := p.Sync(ctx, u); err != nil {
		t.Fatalf("sync promote: %v", err)
	}
	st, _ := p.Status(ctx, []string{email})
	if st[email].Role != "projectOwner" || st[email].Deactivated {
		t.Errorf("after promote want projectOwner/active, got %+v", st[email])
	}

	// Remove all mapped groups: Sync must deactivate (access revoked).
	u.Groups = []string{"unrelated"}
	if err := p.Sync(ctx, u); err != nil {
		t.Fatalf("sync revoke: %v", err)
	}
	st, _ = p.Status(ctx, []string{email})
	if !st[email].Deactivated {
		t.Errorf("after revoking access want deactivated, got %+v", st[email])
	}

	// Re-grant access: Sync must reactivate and set the role.
	u.Groups = []string{"planka-users"}
	if err := p.Sync(ctx, u); err != nil {
		t.Fatalf("sync regrant: %v", err)
	}
	st, _ = p.Status(ctx, []string{email})
	if st[email].Role != "boardUser" || st[email].Deactivated {
		t.Errorf("after re-grant want boardUser/active, got %+v", st[email])
	}
}

// TestIntegrationCheckDetectsMissingSequenceGrant proves the grant probe catches
// the exact prod footgun: a role with SELECT/INSERT/UPDATE on user_account but
// WITHOUT USAGE on next_id_seq passes the schema check yet cannot actually
// insert. Check() must fail (red /healthz) at startup, not at first invite.
func TestIntegrationCheckDetectsMissingSequenceGrant(t *testing.T) {
	ctx := context.Background()
	admin := testPool(t)
	// Everything EXCEPT the sequence grant.
	limited, role := makeInviteRole(t, admin, []string{
		`GRANT SELECT (email, role, is_deactivated) ON user_account`,
		`GRANT INSERT ON user_account`,
		`GRANT UPDATE (is_deactivated, role) ON user_account`,
	})
	p := testProvisioner(t, limited)
	if err := p.Check(ctx); err == nil || !strings.Contains(err.Error(), "next_id_seq") {
		t.Fatalf("want a missing-sequence-grant error, got %v", err)
	}
	// Granting the sequence makes Check pass — confirms that was the only gap.
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SEQUENCE next_id_seq TO `+role); err != nil {
		t.Fatalf("grant sequence: %v", err)
	}
	if err := p.Check(ctx); err != nil {
		t.Fatalf("Check should pass once the sequence is granted, got %v", err)
	}
}

func TestIntegrationProvisionRejectsDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	p := testProvisioner(t, pool)
	email := "int-test-dup@example.org"
	_, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM user_account WHERE lower(email)=$1`, email) })

	u := provision.User{Username: "inttestdup", DisplayName: "Dup", Email: email, Groups: []string{"planka-users"}}
	if err := p.Provision(ctx, u); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := p.Provision(ctx, u); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second insert should be rejected, got %v", err)
	}
}
