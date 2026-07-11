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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// ErrDuplicate is returned by Add when the username or email already exists.
// Callers can errors.Is() this to show a friendly message (the wrapped text
// is self-authored and safe to display) rather than a generic failure.
var ErrDuplicate = errors.New("duplicate user")

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
			// Username compared case-insensitively to match Authelia's
			// case_insensitive search: a lowercase twin of an existing
			// mixed-case name would otherwise pass here and produce a file
			// Authelia refuses to load.
			if strings.EqualFold(existing.Username, u.Username) {
				return fmt.Errorf("%w: username %q already exists", ErrDuplicate, u.Username)
			}
			if strings.EqualFold(existing.Email, u.Email) {
				return fmt.Errorf("%w: email %q already belongs to user %q", ErrDuplicate, u.Email, existing.Username)
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
//
// Authelia writes this same file (in-place, WITHOUT a lock) when a user
// completes a self-service password reset, so the flock only serialises
// portal writers. To avoid clobbering such a write, each attempt re-reads the
// file immediately before the rename and, if it changed since we read it,
// restarts from the fresh content (bounded retries). This shrinks the
// lost-update / torn-read window from the whole parse+encode duration to the
// few microseconds between the final read and the rename.
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

	sweepStaleTemps(dir)

	const attempts = 4
	for attempt := 0; ; attempt++ {
		retry, err := s.mutateOnce(dir, edit, verify)
		if err != nil {
			return err
		}
		if !retry {
			return nil
		}
		if attempt+1 >= attempts {
			return fmt.Errorf("users file kept changing underneath us (concurrent writer?); retries exhausted")
		}
	}
}

// mutateOnce performs one attempt. It returns retry=true (err=nil) when the
// file changed between our read and the rename, signalling the caller to try
// again with fresh content.
func (s *Store) mutateOnce(dir string, edit func(users *yaml.Node) error, verify func(before, after map[string]map[string]any) error) (retry bool, err error) {
	original, err := os.ReadFile(s.Path)
	if err != nil {
		return false, fmt.Errorf("read users file: %w", err)
	}
	doc, err := parseBytes(original)
	if err != nil {
		return false, err
	}
	before, err := snapshot(doc)
	if err != nil {
		return false, err
	}
	users, err := usersMap(doc)
	if err != nil {
		return false, err
	}
	if err := edit(users); err != nil {
		return false, err
	}

	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc.Content[0]); err != nil {
		return false, fmt.Errorf("encode users file: %w", err)
	}
	if err := enc.Close(); err != nil {
		return false, fmt.Errorf("encode users file: %w", err)
	}
	out := []byte(sb.String())

	// Re-parse our own output and prove the mutation — and nothing else —
	// happened before we touch the real file.
	reparsed, err := parseBytes(out)
	if err != nil {
		return false, fmt.Errorf("output failed to re-parse (bug): %w", err)
	}
	after, err := snapshot(reparsed)
	if err != nil {
		return false, fmt.Errorf("output snapshot (bug): %w", err)
	}
	if err := verify(before, after); err != nil {
		return false, fmt.Errorf("post-write verification refused the change: %w", err)
	}

	// Guard against a concurrent (unlocked) Authelia write: if the file no
	// longer matches what we read and edited, discard this attempt and retry.
	if current, err := os.ReadFile(s.Path); err != nil {
		return false, fmt.Errorf("re-read users file: %w", err)
	} else if !bytes.Equal(current, original) {
		return true, nil
	}

	if err := os.WriteFile(s.Path+".bak", original, 0o600); err != nil {
		return false, fmt.Errorf("write backup: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".users_database.yml.tmp*")
	if err != nil {
		return false, fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // no-op after successful rename
	if _, err := tmp.Write(out); err != nil { // CreateTemp already makes it 0600
		tmp.Close()
		return false, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp file: %w", err)
	}
	// Atomic replace: readers (Authelia) see either the old or the new file,
	// never a partial one. The rename raises the Create event Authelia's
	// file watcher reloads on.
	if err := os.Rename(tmpName, s.Path); err != nil {
		return false, fmt.Errorf("rename into place: %w", err)
	}
	// fsync the directory so the rename (a completed invite / offboard) is
	// durable across power loss — the welcome email is sent after we return.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return false, nil
}

// sweepStaleTemps removes leftover temp files from a previous crash between
// CreateTemp and rename. Their names never match Authelia's watch filter, so
// they're harmless, but they shouldn't accumulate. Best-effort.
func sweepStaleTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".users_database.yml.tmp") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func parseBytes(b []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("users file is empty or not a YAML document")
	}
	// Refuse a multi-document file: yaml.Unmarshal silently keeps only the
	// first document, so encoding back would delete the rest. An Authelia
	// users file is always a single document; a second one means we're
	// looking at something we don't understand — fail closed.
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return nil, fmt.Errorf("users file has more than one YAML document; refusing to edit")
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
			// An empty file (`users:` with a null value) is a valid,
			// user-less store — normalise it to an empty mapping in place so
			// the first user can be added. Reject any other non-mapping.
			if m.Kind == yaml.ScalarNode && (m.Tag == "!!null" || m.Value == "") {
				m.Kind = yaml.MappingNode
				m.Tag = "!!map"
				m.Value = ""
				return m, nil
			}
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
		// Compare canonically re-encoded YAML rather than reflect.DeepEqual:
		// yaml.v3 sorts map keys deterministically, and this avoids
		// DeepEqual's NaN != NaN quirk (a `.nan` in any field would otherwise
		// make every user compare unequal and brick all mutations).
		beforeBytes, err1 := yaml.Marshal(before[name])
		afterBytes, err2 := yaml.Marshal(got)
		if err1 != nil || err2 != nil || !bytes.Equal(beforeBytes, afterBytes) {
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
