package planka

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/uppertoe/vps-user-portal/internal/provision"
)

const cfgYAML = `provisioners:
  - type: planka-postgres
    name: planka
    dsn_env: TEST_PLANKA_DSN
    roles:
      planka-admins: admin
      planka-owners: projectOwner
      planka-users: boardUser
`

func loadOne(t *testing.T) *Provisioner {
	t.Helper()
	t.Setenv("TEST_PLANKA_DSN", "postgres://invite:x@localhost:5432/planka")
	path := filepath.Join(t.TempDir(), "provisioners.yaml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	provs, err := provision.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(provs) != 1 || provs[0].Name() != "planka" {
		t.Fatalf("unexpected provisioners: %v", provs)
	}
	return provs[0].(*Provisioner)
}

func TestRoleMappingPrivilegeOrder(t *testing.T) {
	p := loadOne(t)
	for _, tc := range []struct {
		groups []string
		want   string
	}{
		// First YAML-listed match wins: a user in both admin and user groups is an admin.
		{[]string{"planka-users", "planka-admins"}, "admin"},
		{[]string{"planka-owners"}, "projectOwner"},
		{[]string{"planka-users"}, "boardUser"},
		{[]string{"unrelated-group"}, ""}, // out of scope: skipped entirely
		{nil, ""},
	} {
		if got := p.roleFor(tc.groups); got != tc.want {
			t.Errorf("roleFor(%v) = %q, want %q", tc.groups, got, tc.want)
		}
	}
}

func TestLoadRejectsInvalidRole(t *testing.T) {
	t.Setenv("TEST_PLANKA_DSN", "postgres://x")
	path := filepath.Join(t.TempDir(), "provisioners.yaml")
	// "Admin" (wrong case) is not a valid Planka role; must be refused at load.
	yml := "provisioners:\n  - type: planka-postgres\n    dsn_env: TEST_PLANKA_DSN\n    roles:\n      planka-admins: Admin\n"
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Load(path); err == nil {
		t.Error("invalid Planka role accepted")
	}
}

func TestLoadRejectsBadConfig(t *testing.T) {
	for name, yml := range map[string]string{
		"unknown type": "provisioners:\n  - type: nonsense\n",
		"missing dsn_env": "provisioners:\n  - type: planka-postgres\n    roles:\n      g: admin\n",
		"empty roles":     "provisioners:\n  - type: planka-postgres\n    dsn_env: TEST_PLANKA_DSN\n",
	} {
		t.Setenv("TEST_PLANKA_DSN", "postgres://x")
		path := filepath.Join(t.TempDir(), "provisioners.yaml")
		if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := provision.Load(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEmptyPathMeansNoProvisioners(t *testing.T) {
	provs, err := provision.Load("")
	if err != nil || len(provs) != 0 {
		t.Errorf("got %v, %v; want none, nil", provs, err)
	}
}

// Two Planka instances on one VPS (e.g. planka.mch-… and planka.casey-…),
// each its own DSN + group namespace, is a first-class supported config.
func TestTwoPlankaInstances(t *testing.T) {
	t.Setenv("MCH_DSN", "postgres://invite:x@localhost/mch")
	t.Setenv("CASEY_DSN", "postgres://invite:x@localhost/casey")
	yml := `provisioners:
  - type: planka-postgres
    name: planka-mch
    label: MCH Planka
    dsn_env: MCH_DSN
    roles:
      planka-mch-admins: admin
      planka-mch-users: boardUser
  - type: planka-postgres
    name: planka-casey
    label: Casey Planka
    dsn_env: CASEY_DSN
    roles:
      planka-casey-admins: admin
      planka-casey-users: boardUser
`
	path := filepath.Join(t.TempDir(), "provisioners.yaml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	provs, err := provision.Load(path)
	if err != nil {
		t.Fatalf("two instances should load: %v", err)
	}
	if len(provs) != 2 {
		t.Fatalf("want 2 provisioners, got %d", len(provs))
	}
	mch, casey := provs[0].(*Provisioner), provs[1].(*Provisioner)
	// Each only recognises its OWN groups -> a user is provisioned into the
	// instance(s) they're granted, and skipped by the other.
	if mch.roleFor([]string{"planka-mch-users"}) != "boardUser" {
		t.Error("mch should map its own group")
	}
	if mch.roleFor([]string{"planka-casey-users"}) != "" {
		t.Error("mch must NOT match casey's group (would cross-provision)")
	}
	if casey.roleFor([]string{"planka-casey-admins"}) != "admin" {
		t.Error("casey should map its own group")
	}
	if mch.Info().DisplayName != "MCH Planka" || casey.Info().DisplayName != "Casey Planka" {
		t.Error("labels not independent")
	}
}

func TestDuplicateProvisionerNameRejected(t *testing.T) {
	t.Setenv("D1", "postgres://x")
	t.Setenv("D2", "postgres://y")
	yml := `provisioners:
  - {type: planka-postgres, name: planka, dsn_env: D1, roles: {g: admin}}
  - {type: planka-postgres, name: planka, dsn_env: D2, roles: {g: admin}}
`
	path := filepath.Join(t.TempDir(), "provisioners.yaml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Load(path); err == nil {
		t.Error("duplicate provisioner names should be rejected")
	}
}
