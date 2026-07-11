package userstore

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const sample = `# Authelia users database -- hand-maintained; see README.
# Groups map to app roles (planka-admins -> Admin, etc).
users:
  alice:
    displayname: "Alice Example"
    email: alice@example.org
    # NOTE: password set via self-service reset
    password: "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    groups:
      - planka-admins
  bob:
    displayname: Bob Builder
    email: bob@example.org
    password: "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    groups:
      - planka-users
    extra_field: keep-me
`

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users_database.yml")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(path)
}

func TestListParsesUsers(t *testing.T) {
	s := newStore(t)
	users, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	if users[0].Username != "alice" || users[0].Email != "alice@example.org" {
		t.Errorf("unexpected first user: %+v", users[0])
	}
	if users[1].Groups[0] != "planka-users" {
		t.Errorf("unexpected groups: %v", users[1].Groups)
	}
}

func TestAddPreservesCommentsAndUnknownFields(t *testing.T) {
	s := newStore(t)
	hash, err := ThrowawayHash()
	if err != nil {
		t.Fatal(err)
	}
	err = s.Add(User{
		Username:    "carol",
		DisplayName: "Carol New",
		Email:       "Carol@Example.org",
		Groups:      []string{"planka-users"},
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"# Authelia users database -- hand-maintained",
		"# NOTE: password set via self-service reset",
		"extra_field: keep-me",
		"carol@example.org", // stored lowercased
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lost %q:\n%s", want, text)
		}
	}
	users, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[2].Username != "carol" {
		t.Fatalf("carol not appended: %+v", users)
	}
	// Backup of the pre-change content exists.
	bak, err := os.ReadFile(s.Path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if string(bak) != sample {
		t.Error("backup does not match original content")
	}
}

func TestAddRejectsDuplicates(t *testing.T) {
	s := newStore(t)
	hash, _ := ThrowawayHash()
	if err := s.Add(User{Username: "alice", Email: "new@example.org"}, hash); err == nil {
		t.Error("duplicate username accepted")
	}
	if err := s.Add(User{Username: "newuser", Email: "ALICE@example.org"}, hash); err == nil {
		t.Error("duplicate email (case-insensitive) accepted")
	}
	// Failed mutations must leave the file untouched.
	out, _ := os.ReadFile(s.Path)
	if string(out) != sample {
		t.Error("file changed by a rejected mutation")
	}
}

func TestSetGroups(t *testing.T) {
	s := newStore(t)
	if err := s.SetGroups("bob", []string{"planka-owners", "planka-users"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.Get("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Groups) != 2 || u.Groups[0] != "planka-owners" {
		t.Errorf("groups not applied: %v", u.Groups)
	}
	// Alice untouched, comments intact.
	out, _ := os.ReadFile(s.Path)
	if !strings.Contains(string(out), "planka-admins") || !strings.Contains(string(out), "# NOTE: password") {
		t.Error("unrelated content damaged by group edit")
	}
}

func TestDelete(t *testing.T) {
	s := newStore(t)
	if err := s.Delete("bob"); err != nil {
		t.Fatal(err)
	}
	users, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("unexpected users after delete: %+v", users)
	}
	if err := s.Delete("bob"); err == nil {
		t.Error("deleting a missing user should fail")
	}
}

func TestThrowawayHashShape(t *testing.T) {
	h, err := ThrowawayHash()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if !re.MatchString(h) {
		t.Errorf("hash not in expected PHC form: %s", h)
	}
	h2, _ := ThrowawayHash()
	if h == h2 {
		t.Error("two throwaway hashes were identical")
	}
}

func TestDeriveUsername(t *testing.T) {
	for in, want := range map[string]string{
		"John.Smith@rch.org.au": "john.smith",
		"j_smith+tag@x.org":     "j_smithtag",
		"--weird--@x.org":       "weird",
	} {
		if got := DeriveUsername(in); got != want {
			t.Errorf("DeriveUsername(%q) = %q, want %q", in, got, want)
		}
	}
}
