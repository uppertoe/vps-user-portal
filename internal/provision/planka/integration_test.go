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

func TestIntegrationCheckPassesOnRealSchema(t *testing.T) {
	p := testProvisioner(t, testPool(t))
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Check() failed against real Planka schema: %v", err)
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
