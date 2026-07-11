// Package planka implements the planka-postgres provisioner: it pre-creates
// users directly in Planka's database so they can be added to boards and
// assigned to cards BEFORE their first SSO login.
//
// Why direct SQL: with OIDC_ENFORCED=true (this estate's posture) Planka's
// own user-creation API is hard-disabled — the users/create controller
// throws NOT_ENOUGH_RIGHTS. At first OIDC login Planka links the existing
// row by email and marks it isSsoUser, exactly as if it had created the row
// itself.
//
// The row is inserted with is_sso_user=true and password=NULL, so no
// password login path ever exists for it. Offboarding deactivates
// (is_deactivated=true) rather than deleting, preserving card history.
//
// The portal's database role must be narrowly granted:
//
//	GRANT SELECT, INSERT ON user_account TO invite;
//	GRANT UPDATE (is_deactivated, role) ON user_account TO invite;
//
// Schema coupling is guarded by Check(): the columns this package writes are
// asserted against information_schema at startup and periodically, so a
// Planka major upgrade that moves the furniture fails the portal's
// healthcheck instead of corrupting writes.
package planka

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/uppertoe/vps-user-portal/internal/provision"
)

func init() {
	provision.Register("planka-postgres", func(name string, cfg *yaml.Node) (provision.Provisioner, error) {
		return newFromConfig(name, cfg)
	})
}

type roleRule struct {
	Group string
	Role  string
}

type Provisioner struct {
	name string
	pool *pgxpool.Pool
	// roles maps SSO groups to Planka roles in privilege order (first match
	// wins), e.g. planka-admins->admin, planka-owners->projectOwner,
	// planka-users->boardUser.
	roles []roleRule
}

func newFromConfig(name string, cfg *yaml.Node) (*Provisioner, error) {
	var raw struct {
		DSNEnv string    `yaml:"dsn_env"`
		Roles  yaml.Node `yaml:"roles"`
	}
	if err := cfg.Decode(&raw); err != nil {
		return nil, err
	}
	if raw.DSNEnv == "" {
		return nil, fmt.Errorf("planka-postgres requires dsn_env (name of the env var holding the DSN)")
	}
	dsn := os.Getenv(raw.DSNEnv)
	if dsn == "" {
		return nil, fmt.Errorf("env var %s (from dsn_env) is empty", raw.DSNEnv)
	}
	// Decode roles from the mapping NODE, not into a Go map: mapping order in
	// the YAML is the privilege order and must be preserved.
	if raw.Roles.Kind != yaml.MappingNode || len(raw.Roles.Content) == 0 {
		return nil, fmt.Errorf("planka-postgres requires a non-empty roles mapping (group: plankaRole)")
	}
	var rules []roleRule
	for i := 0; i+1 < len(raw.Roles.Content); i += 2 {
		rules = append(rules, roleRule{
			Group: raw.Roles.Content[i].Value,
			Role:  raw.Roles.Content[i+1].Value,
		})
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres pool: %w", err)
	}
	return &Provisioner{name: name, pool: pool, roles: rules}, nil
}

func (p *Provisioner) Name() string { return p.name }

// roleFor resolves the Planka role for a group set; "" = out of scope.
func (p *Provisioner) roleFor(groups []string) string {
	set := make(map[string]bool, len(groups))
	for _, g := range groups {
		set[g] = true
	}
	for _, r := range p.roles {
		if set[r.Group] {
			return r.Role
		}
	}
	return ""
}

// requiredColumns are the user_account columns this package touches, with
// the properties it relies on.
var requiredColumns = []string{"id", "email", "password", "role", "name", "username", "is_sso_user", "is_deactivated", "created_at"}

func (p *Provisioner) Check(ctx context.Context) error {
	rows, err := p.pool.Query(ctx, `
		SELECT column_name, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'user_account'`)
	if err != nil {
		return fmt.Errorf("query user_account schema: %w", err)
	}
	defer rows.Close()
	type col struct {
		nullable   bool
		hasDefault bool
	}
	cols := map[string]col{}
	for rows.Next() {
		var name, nullable string
		var def *string
		if err := rows.Scan(&name, &nullable, &def); err != nil {
			return err
		}
		cols[name] = col{nullable: nullable == "YES", hasDefault: def != nil}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(cols) == 0 {
		return fmt.Errorf("user_account table not found — wrong database or Planka schema moved")
	}
	var missing []string
	for _, c := range requiredColumns {
		if _, ok := cols[c]; !ok {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("user_account is missing expected columns %v — Planka schema drift, do not provision", missing)
	}
	if !cols["id"].hasDefault {
		return fmt.Errorf("user_account.id has no default — this provisioner relies on Planka's id generator")
	}
	if !cols["password"].nullable {
		return fmt.Errorf("user_account.password is NOT NULL — SSO-only rows need it nullable")
	}
	return nil
}

func (p *Provisioner) Provision(ctx context.Context, u provision.User) error {
	role := p.roleFor(u.Groups)
	if role == "" {
		return nil // no mapped group: this app is out of scope for the user
	}
	email := strings.ToLower(u.Email)
	var exists bool
	if err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_account WHERE lower(email) = $1)`, email).Scan(&exists); err != nil {
		return fmt.Errorf("check existing user: %w", err)
	}
	if exists {
		return fmt.Errorf("a Planka user with email %s already exists", email)
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO user_account (email, name, username, role, is_sso_user, is_deactivated, created_at)
		VALUES ($1, $2, $3, $4, true, false, now())`,
		email, u.DisplayName, u.Username, role)
	if err != nil {
		return fmt.Errorf("insert user_account row: %w", err)
	}
	return nil
}

func (p *Provisioner) Deprovision(ctx context.Context, u provision.User) error {
	// Deactivate, never delete: card assignments and history must survive.
	// 0 rows affected is fine — the user was out of this app's scope.
	_, err := p.pool.Exec(ctx,
		`UPDATE user_account SET is_deactivated = true WHERE lower(email) = $1`,
		strings.ToLower(u.Email))
	if err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}
	return nil
}

func (p *Provisioner) Status(ctx context.Context, emails []string) (map[string]provision.AppStatus, error) {
	lower := make([]string, len(emails))
	for i, e := range emails {
		lower[i] = strings.ToLower(e)
	}
	rows, err := p.pool.Query(ctx, `
		SELECT lower(email), role, is_deactivated
		FROM user_account WHERE lower(email) = ANY($1)`, lower)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]provision.AppStatus)
	for rows.Next() {
		var email, role string
		var deactivated bool
		if err := rows.Scan(&email, &role, &deactivated); err != nil {
			return nil, err
		}
		out[email] = provision.AppStatus{Present: true, Role: role, Deactivated: deactivated}
	}
	return out, rows.Err()
}
