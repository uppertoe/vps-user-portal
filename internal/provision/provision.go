// Package provision defines the pluggable app-provisioner interface: how a
// newly invited SSO user gets pre-created inside downstream applications
// (so they can be referenced — e.g. assigned to Planka cards — before their
// first login), and deactivated there at offboarding.
//
// Provisioners are configured via a mounted provisioners.yaml:
//
//	provisioners:
//	  - type: planka-postgres
//	    name: planka
//	    dsn_env: PLANKA_DSN        # env var holding the postgres DSN
//	    roles:                     # SSO group -> app role (first match wins,
//	      planka-admins: admin     #   listed here in privilege order)
//	      planka-owners: projectOwner
//	      planka-users: boardUser
//
// A user matching none of a provisioner's role groups is simply out of that
// app's scope: skipped at provision time, untouched at deprovision time.
package provision

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// User is the subset of the SSO user a provisioner needs.
type User struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}

// AppStatus is one app's view of one user, for the portal's list view.
type AppStatus struct {
	Present     bool
	Role        string
	Deactivated bool
}

// AppInfo is display metadata about a managed app, for the UI ("which apps
// does this portal control?").
type AppInfo struct {
	Name        string // internal provisioner name, e.g. "planka"
	DisplayName string // human name, e.g. "Planka" (falls back to Name)
	URL         string // optional public URL, e.g. https://planka.example.org
}

// Provisioner pre-creates, updates and deactivates users in one downstream app.
type Provisioner interface {
	// Name labels this provisioner in the UI and audit log.
	Name() string
	// Info returns display metadata for the UI.
	Info() AppInfo
	// Check asserts the integration's assumptions (e.g. database schema)
	// hold. It runs at startup and periodically; failure turns the portal's
	// health endpoint red so a drifted app upgrade is caught loudly before
	// any bad writes.
	Check(ctx context.Context) error
	// Provision creates the user in the app. Idempotence: an already-present
	// user (matched by email) is an error — the portal checks first.
	// Called AFTER the SSO user store write: if it fails, the invite still
	// self-heals (the app creates the user at first SSO login); the portal
	// surfaces the failure to the admin and the audit log.
	Provision(ctx context.Context, u User) error
	// Sync reconciles an EXISTING app user with the portal's current view
	// after an access (group) change: update the mapped role, reactivate a
	// user who regained access, or deactivate one whose groups no longer
	// grant any role. A user with no app row is left alone (they get the
	// right role when the app creates them at first login). This is what
	// makes an access edit take effect immediately rather than at next login.
	Sync(ctx context.Context, u User) error
	// Deprovision deactivates (never deletes) the user in the app, so
	// history survives offboarding. Called AFTER the SSO entry is removed —
	// severing SSO is the security-critical step and goes first.
	Deprovision(ctx context.Context, u User) error
	// Status reports app-side state for the given emails (lowercase).
	Status(ctx context.Context, emails []string) (map[string]AppStatus, error)
}

// Factory builds a provisioner from its yaml config node.
type Factory func(name string, cfg *yaml.Node) (Provisioner, error)

var factories = map[string]Factory{}

// Register makes a provisioner type available to Load. Called from the
// implementation packages' init().
func Register(typ string, f Factory) { factories[typ] = f }

type fileConfig struct {
	Provisioners []struct {
		Type string    `yaml:"type"`
		Name string    `yaml:"name"`
		Rest yaml.Node `yaml:",inline"`
	} `yaml:"provisioners"`
}

// Load reads provisioners.yaml. path == "" yields no provisioners
// (Authelia-only mode).
func Load(path string) ([]Provisioner, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provisioners config: %w", err)
	}
	// Two-pass: get type/name, then hand the raw entry node to the factory.
	var generic struct {
		Provisioners []yaml.Node `yaml:"provisioners"`
	}
	if err := yaml.Unmarshal(b, &generic); err != nil {
		return nil, fmt.Errorf("parse provisioners config: %w", err)
	}
	var out []Provisioner
	seen := map[string]bool{}
	for i, node := range generic.Provisioners {
		var head struct {
			Type string `yaml:"type"`
			Name string `yaml:"name"`
		}
		if err := node.Decode(&head); err != nil {
			return nil, fmt.Errorf("provisioner %d: %w", i, err)
		}
		f, ok := factories[head.Type]
		if !ok {
			return nil, fmt.Errorf("provisioner %d: unknown type %q", i, head.Type)
		}
		if head.Name == "" {
			head.Name = head.Type
		}
		// Names must be unique: they key the per-app status map and label the
		// UI columns. Running two of the same type (e.g. two Planka instances)
		// is fully supported — just give each a distinct name.
		if seen[head.Name] {
			return nil, fmt.Errorf("duplicate provisioner name %q — give each instance (e.g. two Planka deployments) a unique name", head.Name)
		}
		seen[head.Name] = true
		n := node
		p, err := f(head.Name, &n)
		if err != nil {
			return nil, fmt.Errorf("provisioner %q: %w", head.Name, err)
		}
		out = append(out, p)
	}
	return out, nil
}
