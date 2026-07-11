// Package userstore mutates Authelia's file-backend user database
// (users_database.yml) safely.
//
// This file is the SSO estate's user store: a bad write here is an
// authentication incident. Every mutation therefore:
//
//  1. takes an exclusive flock on a sidecar lock file (serialises portal
//     writers; Authelia's own password-reset persistence takes no lock, so a
//     reset landing in the same instant remains a documented, tiny race);
//  2. edits the parsed yaml.Node tree rather than decode/re-encode structs,
//     so comments, key order and unknown fields survive round-trips and the
//     file stays hand-maintainable;
//  3. re-parses its own output and verifies invariants (untouched users are
//     deep-equal, exactly the intended mutation happened) before the file is
//     replaced — a serialisation bug cannot silently corrupt the store;
//  4. keeps the previous content as <file>.bak, then atomically renames the
//     new content into place. The rename lands as an fsnotify Create event in
//     the watched directory, which triggers Authelia's hot reload — this is
//     why the file must be bind-mounted via its parent DIRECTORY (a
//     single-file bind mount pins the inode and would keep Authelia reading
//     the pre-rename file forever).
package userstore

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// User is the portal's view of one users_database.yml entry. Unknown fields
// in the file are preserved by the node-tree editing but are not surfaced.
type User struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
	Disabled    bool
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidUsername reports whether s is acceptable as a new username.
func ValidUsername(s string) bool { return usernameRe.MatchString(s) }

// DeriveUsername proposes a username from an email's local part.
func DeriveUsername(email string) string {
	local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
	var b strings.Builder
	for _, r := range local {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "._-")
}

// Store reads and mutates one users_database.yml.
type Store struct {
	Path string
}

func New(path string) *Store { return &Store{Path: path} }

// List returns all users in file order.
func (s *Store) List() ([]User, error) {
	doc, err := s.parseFile()
	if err != nil {
		return nil, err
	}
	usersNode, err := usersMap(doc)
	if err != nil {
		return nil, err
	}
	var out []User
	for i := 0; i+1 < len(usersNode.Content); i += 2 {
		out = append(out, decodeUser(usersNode.Content[i].Value, usersNode.Content[i+1]))
	}
	return out, nil
}

// Get returns one user by username.
func (s *Store) Get(username string) (User, error) {
	users, err := s.List()
	if err != nil {
		return User{}, err
	}
	for _, u := range users {
		if u.Username == username {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("user %q not found", username)
}

// Add appends a new user. passwordHash must be a valid Authelia password
// digest (for invited users, a random throwaway argon2id hash — the account
// stays unusable until the owner completes self-service reset).
func (s *Store) Add(u User, passwordHash string) error {
	if !ValidUsername(u.Username) {
		return fmt.Errorf("invalid username %q", u.Username)
	}
	return s.mutate(func(users *yaml.Node) error {
		for i := 0; i+1 < len(users.Content); i += 2 {
			existing := decodeUser(users.Content[i].Value, users.Content[i+1])
			if existing.Username == u.Username {
				return fmt.Errorf("username %q already exists", u.Username)
			}
			if strings.EqualFold(existing.Email, u.Email) {
				return fmt.Errorf("email %q already belongs to user %q", u.Email, existing.Username)
			}
		}
		key := scalarNode(u.Username)
		val := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		val.Content = append(val.Content,
			scalarNode("displayname"), scalarNode(u.DisplayName),
			scalarNode("email"), scalarNode(strings.ToLower(u.Email)),
			scalarNode("password"), scalarNode(passwordHash),
			scalarNode("groups"), seqNode(u.Groups),
		)
		users.Content = append(users.Content, key, val)
		return nil
	}, func(before, after map[string]map[string]any) error {
		if err := untouchedEqual(before, after, u.Username); err != nil {
			return err
		}
		added, ok := after[u.Username]
		if !ok {
			return fmt.Errorf("added user %q missing from output", u.Username)
		}
		if _, had := before[u.Username]; had {
			return fmt.Errorf("user %q unexpectedly existed before add", u.Username)
		}
		if got := added["email"]; got != strings.ToLower(u.Email) {
			return fmt.Errorf("added user has email %v, want %s", got, strings.ToLower(u.Email))
		}
		if len(after) != len(before)+1 {
			return fmt.Errorf("user count went %d -> %d, want +1", len(before), len(after))
		}
		return nil
	})
}

// SetGroups replaces a user's group list.
func (s *Store) SetGroups(username string, groups []string) error {
	return s.mutate(func(users *yaml.Node) error {
		val := findUser(users, username)
		if val == nil {
			return fmt.Errorf("user %q not found", username)
		}
		setMapField(val, "groups", seqNode(groups))
		return nil
	}, func(before, after map[string]map[string]any) error {
		if err := untouchedEqual(before, after, username); err != nil {
			return err
		}
		if len(after) != len(before) {
			return fmt.Errorf("user count changed during group edit")
		}
		got, _ := after[username]["groups"].([]any)
		if !sameStrings(got, groups) {
			return fmt.Errorf("groups for %q not applied as requested", username)
		}
		return nil
	})
}

// Delete removes a user entirely (offboarding: severs SSO).
func (s *Store) Delete(username string) error {
	return s.mutate(func(users *yaml.Node) error {
		for i := 0; i+1 < len(users.Content); i += 2 {
			if users.Content[i].Value == username {
				users.Content = append(users.Content[:i], users.Content[i+2:]...)
				return nil
			}
		}
		return fmt.Errorf("user %q not found", username)
	}, func(before, after map[string]map[string]any) error {
		if err := untouchedEqual(before, after, username); err != nil {
			return err
		}
		if _, still := after[username]; still {
			return fmt.Errorf("user %q still present after delete", username)
		}
		if len(after) != len(before)-1 {
			return fmt.Errorf("user count went %d -> %d, want -1", len(before), len(after))
		}
		return nil
	})
}

// --- mutation machinery ---

// mutate applies edit to the users mapping node, then re-parses the encoded
// output and runs verify(before, after) on semantic snapshots. Only if verify
// passes is the file (atomically) replaced; the prior content is kept at
// <path>.bak.
func (s *Store) mutate(edit func(users *yaml.Node) error, verify func(before, after map[string]map[string]any) error) error {
	dir := filepath.Dir(s.Path)

	lock, err := os.OpenFile(filepath.Join(dir, ".portal.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck

	original, err := os.ReadFile(s.Path)
	if err != nil {
		return fmt.Errorf("read users file: %w", err)
	}
	doc, err := parseBytes(original)
	if err != nil {
		return err
	}
	before, err := snapshot(doc)
	if err != nil {
		return err
	}
	users, err := usersMap(doc)
	if err != nil {
		return err
	}
	if err := edit(users); err != nil {
		return err
	}

	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc.Content[0]); err != nil {
		return fmt.Errorf("encode users file: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encode users file: %w", err)
	}
	out := []byte(sb.String())

	// Re-parse our own output and prove the mutation — and nothing else —
	// happened before we touch the real file.
	reparsed, err := parseBytes(out)
	if err != nil {
		return fmt.Errorf("output failed to re-parse (bug): %w", err)
	}
	after, err := snapshot(reparsed)
	if err != nil {
		return fmt.Errorf("output snapshot (bug): %w", err)
	}
	if err := verify(before, after); err != nil {
		return fmt.Errorf("post-write verification refused the change: %w", err)
	}

	if err := os.WriteFile(s.Path+".bak", original, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".users_database.yml.tmp*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	// Atomic replace: readers (Authelia) see either the old or the new file,
	// never a partial one. The rename raises the Create event Authelia's
	// file watcher reloads on.
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

func parseBytes(b []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("users file is empty or not a YAML document")
	}
	return &doc, nil
}

func (s *Store) parseFile() (*yaml.Node, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	return parseBytes(b)
}

// usersMap returns the mapping node under the top-level "users" key.
func usersMap(doc *yaml.Node) (*yaml.Node, error) {
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("users file root is not a mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "users" {
			m := root.Content[i+1]
			if m.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("'users' is not a mapping")
			}
			return m, nil
		}
	}
	return nil, fmt.Errorf("users file has no top-level 'users' key")
}

func findUser(users *yaml.Node, username string) *yaml.Node {
	for i := 0; i+1 < len(users.Content); i += 2 {
		if users.Content[i].Value == username {
			return users.Content[i+1]
		}
	}
	return nil
}

func setMapField(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, scalarNode(key), val)
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func seqNode(items []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, it := range items {
		n.Content = append(n.Content, scalarNode(it))
	}
	return n
}

func decodeUser(username string, val *yaml.Node) User {
	var raw struct {
		DisplayName string   `yaml:"displayname"`
		Email       string   `yaml:"email"`
		Groups      []string `yaml:"groups"`
		Disabled    bool     `yaml:"disabled"`
	}
	_ = val.Decode(&raw)
	return User{
		Username:    username,
		DisplayName: raw.DisplayName,
		Email:       raw.Email,
		Groups:      raw.Groups,
		Disabled:    raw.Disabled,
	}
}

// snapshot decodes every user entry to a generic map, so verification also
// covers fields the portal doesn't know about.
func snapshot(doc *yaml.Node) (map[string]map[string]any, error) {
	users, err := usersMap(doc)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(users.Content)/2)
	for i := 0; i+1 < len(users.Content); i += 2 {
		var m map[string]any
		if err := users.Content[i+1].Decode(&m); err != nil {
			return nil, fmt.Errorf("decode user %q: %w", users.Content[i].Value, err)
		}
		out[users.Content[i].Value] = m
	}
	return out, nil
}

// untouchedEqual asserts every user other than exempt is byte-for-byte
// semantically identical between the two snapshots.
func untouchedEqual(before, after map[string]map[string]any, exempt string) error {
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == exempt {
			continue
		}
		got, ok := after[name]
		if !ok {
			return fmt.Errorf("user %q vanished during an unrelated change", name)
		}
		if !reflect.DeepEqual(before[name], got) {
			return fmt.Errorf("user %q was modified during an unrelated change", name)
		}
	}
	for name := range after {
		if name == exempt {
			continue
		}
		if _, ok := before[name]; !ok {
			return fmt.Errorf("user %q appeared during an unrelated change", name)
		}
	}
	return nil
}

func sameStrings(got []any, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, g := range got {
		s, ok := g.(string)
		if !ok || s != want[i] {
			return false
		}
	}
	return true
}
