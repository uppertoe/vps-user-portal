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
