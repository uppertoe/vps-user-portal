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
//	GRANT USAGE ON SEQUENCE next_id_seq TO invite;
//
// The sequence grant is easy to miss but required: user_account.id defaults to
// next_id(), a plain (non-SECURITY DEFINER) function that calls
// nextval('next_id_seq'), so the INSERT runs that nextval as the invite role.
// Without USAGE on the sequence every invite fails with "permission denied for
// sequence next_id_seq".
//
// Both schema coupling AND these grants are guarded by Check(): the columns
// this package writes are asserted against information_schema, and the role's
// INSERT/UPDATE/sequence privileges are probed, at startup and periodically —
// so a Planka major upgrade that moves the furniture, or a missing grant, fails
// the portal's healthcheck instead of corrupting writes or failing per-invite.
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

// validPlankaRoles is Planka's user_account.role value set (from its model's
// isIn validation; the DB column itself has no CHECK). The portal's roles:
// mapping MUST also agree with the Planka deployment's OIDC_ADMIN_ROLES /
// OIDC_PROJECT_OWNER_ROLES / OIDC_BOARD_USER_ROLES env: at first OIDC login
// Planka re-derives role from the groups claim and overwrites the pre-seeded
// value, so a mismatch silently demotes users after their first login.
var validPlankaRoles = map[string]bool{"admin": true, "projectOwner": true, "boardUser": true}

type Provisioner struct {
	name    string
	label   string
	url     string
	pool    *pgxpool.Pool
	// roles maps SSO groups to Planka roles in privilege order (first match
	// wins), e.g. planka-admins->admin, planka-owners->projectOwner,
	// planka-users->boardUser.
	roles []roleRule
}

func newFromConfig(name string, cfg *yaml.Node) (*Provisioner, error) {
	var raw struct {
		DSNEnv string    `yaml:"dsn_env"`
		Label  string    `yaml:"label"`
		URL    string    `yaml:"url"`
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
		group := raw.Roles.Content[i].Value
		role := raw.Roles.Content[i+1].Value
		// user_account.role is plain text with no CHECK constraint — a typo
		// like "Admin" or "board_user" would insert a user Planka treats as
		// having no role. Reject unknown roles (and empty group/role from a
		// non-scalar YAML value) at startup rather than minting broken users.
		if group == "" || role == "" {
			return nil, fmt.Errorf("planka-postgres: empty group or role in the roles mapping")
		}
		if !validPlankaRoles[role] {
			return nil, fmt.Errorf("planka-postgres: %q is not a valid Planka role (want one of admin, projectOwner, boardUser)", role)
		}
		rules = append(rules, roleRule{Group: group, Role: role})
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres pool: %w", err)
	}
	return &Provisioner{name: name, label: raw.Label, url: raw.URL, pool: pool, roles: rules}, nil
}

func (p *Provisioner) Name() string { return p.name }

func (p *Provisioner) Info() provision.AppInfo {
	label := p.label
	if label == "" {
		label = p.name
	}
	return provision.AppInfo{Name: p.name, DisplayName: label, URL: p.url}
}

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

// insertColumns is the set of user_account columns Provision writes. It is
// the single source of truth for both the INSERT below and Check()'s
// drift assertion: every NOT NULL column that lacks a database default MUST
// appear here, or the insert fails at runtime. Planka sets its user-preference
// columns in the application layer (Objection.js model defaults), NOT in the
// database, so a raw insert has to supply them itself — verified against a
// live `ghcr.io/plankanban/planka:latest` schema. The preference VALUES here
// mirror Planka's own account-creation defaults, so an SSO-provisioned user is
// indistinguishable from a UI-created one.
//
// id (bigint, default next_id()) and password (nullable, left NULL) are
// deliberately omitted; created_at is nullable but set for cleanliness.
var insertColumns = []string{
	"email", "name", "username", "role", "is_sso_user", "is_deactivated",
	"subscribe_to_own_cards", "subscribe_to_card_when_commenting",
	"turn_off_recent_card_highlighting", "enable_favorites_by_default",
	"default_editor_mode", "default_home_view", "default_projects_order",
	"created_at",
}

func (p *Provisioner) Check(ctx context.Context) error {
	// The drift guarantee: enumerate every column Postgres will REQUIRE on an
	// insert (NOT NULL and no server-side default) and assert it is one we
	// supply. If a future Planka version adds such a column, this fails —
	// turning /healthz red — instead of letting the insert blow up per-user
	// at provision time. Also confirms id keeps a default and password stays
	// nullable (the two shape assumptions the insert relies on).
	rows, err := p.pool.Query(ctx, `
		SELECT column_name, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'user_account'`)
	if err != nil {
		return fmt.Errorf("query user_account schema: %w", err)
	}
	defer rows.Close()

	provided := make(map[string]bool, len(insertColumns))
	for _, c := range insertColumns {
		provided[c] = true
	}
	var (
		found          int
		idHasDefault   bool
		passwordExists bool
		passwordNull   bool
		unmet          []string
	)
	for rows.Next() {
		var name, nullable string
		var def *string
		if err := rows.Scan(&name, &nullable, &def); err != nil {
			return err
		}
		found++
		switch name {
		case "id":
			idHasDefault = def != nil
		case "password":
			passwordExists = true
			passwordNull = nullable == "YES"
		}
		// A column the DB will demand but we don't write == certain insert failure.
		if nullable == "NO" && def == nil && !provided[name] {
			unmet = append(unmet, name)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("user_account table not found — wrong database or Planka schema moved")
	}
	if len(unmet) > 0 {
		return fmt.Errorf("user_account has required columns this provisioner does not set %v — Planka schema drift, refusing to provision", unmet)
	}
	if !idHasDefault {
		return fmt.Errorf("user_account.id has no default — this provisioner relies on Planka's id generator")
	}
	if !passwordExists || !passwordNull {
		return fmt.Errorf("user_account.password is missing or NOT NULL — SSO-only rows need it nullable")
	}
	return p.checkGrants(ctx)
}

// checkGrants probes that the connection's role actually holds the privileges
// Provision/Sync need, so a mis-granted role turns /healthz red at startup
// rather than failing silently on the first invite. Probing (has_*_privilege)
// consumes nothing — it does not call nextval, so it never burns an id.
//
// The sequence grant is the subtle one: id defaults to next_id(), which does
// nextval('next_id_seq') as the caller, so INSERT needs USAGE on that sequence.
// If Planka ever renames it, to_regclass returns NULL and we skip the sequence
// probe (the id-default / insert path then surfaces the real problem) rather
// than emit a false failure.
func (p *Provisioner) checkGrants(ctx context.Context) error {
	var canSelect, canInsert, canDeact, canRole, seqOK bool
	if err := p.pool.QueryRow(ctx, `
		SELECT has_table_privilege(current_user, 'user_account', 'SELECT'),
		       has_table_privilege(current_user, 'user_account', 'INSERT'),
		       has_column_privilege(current_user, 'user_account', 'is_deactivated', 'UPDATE'),
		       has_column_privilege(current_user, 'user_account', 'role', 'UPDATE'),
		       CASE WHEN to_regclass('next_id_seq') IS NULL THEN true
		            ELSE has_sequence_privilege(current_user, 'next_id_seq', 'USAGE') END`).
		Scan(&canSelect, &canInsert, &canDeact, &canRole, &seqOK); err != nil {
		return fmt.Errorf("probe user_account privileges: %w", err)
	}
	var missing []string
	if !canSelect || !canInsert {
		missing = append(missing, "GRANT SELECT, INSERT ON user_account TO <role>;")
	}
	if !canDeact || !canRole {
		missing = append(missing, "GRANT UPDATE (is_deactivated, role) ON user_account TO <role>;")
	}
	if !seqOK {
		missing = append(missing, "GRANT USAGE ON SEQUENCE next_id_seq TO <role>;")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the database role is missing grants — run: %s", strings.Join(missing, " "))
	}
	return nil
}

// Planka user-preference defaults (see insertColumns). Kept as named
// constants so the intent — "match Planka's own new-account defaults" — is
// explicit and one-line auditable against the app's model.
const (
	prefSubscribeToOwnCards      = false
	prefSubscribeWhenCommenting  = true
	prefTurnOffRecentHighlight   = false
	prefEnableFavoritesByDefault = true
	prefDefaultEditorMode        = "wysiwyg"
	prefDefaultHomeView          = "groupedProjects"
	prefDefaultProjectsOrder     = "byDefault"
)

func (p *Provisioner) Provision(ctx context.Context, u provision.User) error {
	role := p.roleFor(u.Groups)
	if role == "" {
		return nil // no mapped group: this app is out of scope for the user
	}
	// Planka stores and looks up email lowercased, and the portal lowercases at
	// intake, so an exact match is both correct and able to use the unique
	// index (a lower(email) predicate would seq-scan and could also match a
	// legacy mixed-case row Planka itself would treat as distinct).
	email := strings.ToLower(u.Email)
	// The unique constraint on email is the real guard against duplicates;
	// this pre-check just yields a friendlier message. ON CONFLICT DO NOTHING
	// closes the check-then-insert race: a concurrent invite that slips
	// between the check and the insert affects 0 rows rather than erroring.
	var exists bool
	if err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_account WHERE email = $1)`, email).Scan(&exists); err != nil {
		return fmt.Errorf("check existing user: %w", err)
	}
	if exists {
		return fmt.Errorf("a Planka user with email %s already exists", email)
	}
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO user_account
			(email, name, username, role, is_sso_user, is_deactivated,
			 subscribe_to_own_cards, subscribe_to_card_when_commenting,
			 turn_off_recent_card_highlighting, enable_favorites_by_default,
			 default_editor_mode, default_home_view, default_projects_order,
			 created_at)
		VALUES ($1, $2, $3, $4, true, false, $5, $6, $7, $8, $9, $10, $11, now())
		ON CONFLICT (email) DO NOTHING`,
		email, u.DisplayName, u.Username, role,
		prefSubscribeToOwnCards, prefSubscribeWhenCommenting,
		prefTurnOffRecentHighlight, prefEnableFavoritesByDefault,
		prefDefaultEditorMode, prefDefaultHomeView, prefDefaultProjectsOrder)
	if err != nil {
		return fmt.Errorf("insert user_account row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("a Planka user with email %s already exists", email)
	}
	return nil
}

// Sync reconciles an EXISTING Planka user with the portal's current view
// after an access (group) change. If the user's groups grant a role, set that
// role and clear is_deactivated (re-granting access reactivates them); if they
// grant no role, deactivate (access revoked). A user with no Planka row is
// left untouched (0 rows affected) — Planka creates them with the right role
// at first login. This makes an access edit take effect immediately for users
// already in Planka, rather than only at their next login. The role we set
// equals what Planka's OIDC mapping would set at login (same documented
// group->role contract), so there is no flip-flop.
func (p *Provisioner) Sync(ctx context.Context, u provision.User) error {
	email := strings.ToLower(u.Email)
	if role := p.roleFor(u.Groups); role != "" {
		if _, err := p.pool.Exec(ctx,
			`UPDATE user_account SET role = $2, is_deactivated = false WHERE email = $1`,
			email, role); err != nil {
			return fmt.Errorf("update user role: %w", err)
		}
		return nil
	}
	// No mapped group -> access revoked for this app: deactivate if present.
	if _, err := p.pool.Exec(ctx,
		`UPDATE user_account SET is_deactivated = true WHERE email = $1`, email); err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}
	return nil
}

func (p *Provisioner) Deprovision(ctx context.Context, u provision.User) error {
	// Deactivate, never delete: card assignments and history must survive.
	// 0 rows affected is fine — the user was out of this app's scope.
	_, err := p.pool.Exec(ctx,
		`UPDATE user_account SET is_deactivated = true WHERE email = $1`,
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
