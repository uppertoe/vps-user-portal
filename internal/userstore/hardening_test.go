package userstore

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func storeWith(t *testing.T, content string) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users_database.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(path)
}

func TestAddToEmptyStore(t *testing.T) {
	// `users:` with a null value is a valid, user-less store.
	s := storeWith(t, "users:\n")
	h, _ := ThrowawayHash()
	if err := s.Add(User{Username: "first", DisplayName: "First", Email: "first@example.org", Groups: []string{"g"}}, h); err != nil {
		t.Fatalf("adding first user to empty store failed: %v", err)
	}
	users, err := s.List()
	if err != nil || len(users) != 1 || users[0].Username != "first" {
		t.Fatalf("first user not added: %+v err=%v", users, err)
	}
}

func TestMultiDocumentRefused(t *testing.T) {
	s := storeWith(t, sample+"---\nmalicious: second-doc\n")
	h, _ := ThrowawayHash()
	err := s.Add(User{Username: "carol", Email: "carol@example.org", Groups: []string{"g"}}, h)
	if err == nil {
		t.Fatal("multi-document file should be refused")
	}
	// Original must be untouched.
	out, _ := os.ReadFile(s.Path)
	if string(out) != sample+"---\nmalicious: second-doc\n" {
		t.Error("refused mutation still altered the file")
	}
}

func TestDuplicateErrorIsSentinel(t *testing.T) {
	s := newStore(t) // from userstore_test.go: alice + bob
	h, _ := ThrowawayHash()
	err := s.Add(User{Username: "fresh", DisplayName: "x", Email: "Alice@Example.org", Groups: []string{"g"}}, h)
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate email (case-insensitive) should be ErrDuplicate, got %v", err)
	}
}

func TestCaseInsensitiveUsernameTwinRefused(t *testing.T) {
	// A file hand-edited to contain a mixed-case username; adding its
	// lowercase twin would produce a file Authelia (case_insensitive) rejects.
	s := storeWith(t, `users:
  Alice:
    displayname: Alice
    email: alice@example.org
    password: "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    groups: [planka-admins]
`)
	h, _ := ThrowawayHash()
	err := s.Add(User{Username: "alice", DisplayName: "x", Email: "new@example.org", Groups: []string{"g"}}, h)
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("lowercase twin of a mixed-case username should be ErrDuplicate, got %v", err)
	}
}

func TestConcurrentWritesSerialiseAndAllLand(t *testing.T) {
	// Exercise the flock + retry path: many concurrent Adds must all succeed
	// and the final file must contain every user exactly once.
	s := newStore(t)
	h, _ := ThrowawayHash()
	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := User{
				Username:    "user" + string(rune('a'+i)),
				DisplayName: "User",
				Email:       "user" + string(rune('a'+i)) + "@example.org",
				Groups:      []string{"planka-users"},
			}
			errs[i] = s.Add(u, h)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent add %d failed: %v", i, err)
		}
	}
	users, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != n+2 { // + alice, bob
		t.Errorf("expected %d users, got %d", n+2, len(users))
	}
	seen := map[string]bool{}
	for _, u := range users {
		if seen[u.Username] {
			t.Errorf("duplicate user in file: %s", u.Username)
		}
		seen[u.Username] = true
	}
}

func TestStaleTempSwept(t *testing.T) {
	s := newStore(t)
	dir := filepath.Dir(s.Path)
	// Simulate a crash-leftover temp file.
	stale := filepath.Join(dir, ".users_database.yml.tmp-crash")
	if err := os.WriteFile(stale, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, _ := ThrowawayHash()
	if err := s.Add(User{Username: "z", DisplayName: "Z", Email: "z@example.org", Groups: []string{"g"}}, h); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale temp file was not swept")
	}
}
