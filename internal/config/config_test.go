package config

import "testing"

func TestParseLabels(t *testing.T) {
	m := parseLabels("planka-users=Board member;planka-admins=Administrator; junk ; =nolabel;nokey=")
	if m["planka-users"] != "Board member" || m["planka-admins"] != "Administrator" {
		t.Errorf("labels not parsed: %v", m)
	}
	if len(m) != 2 {
		t.Errorf("malformed pairs should be skipped, got %v", m)
	}
}

func TestGroupOptionsFallsBackToRawName(t *testing.T) {
	c := &Config{
		Groups:      []string{"planka-users", "planka-owners"},
		GroupLabels: map[string]string{"planka-users": "Board member"},
	}
	opts := c.GroupOptions()
	if len(opts) != 2 {
		t.Fatalf("want 2 options, got %d", len(opts))
	}
	if opts[0].Value != "planka-users" || opts[0].Label != "Board member" {
		t.Errorf("labelled option wrong: %+v", opts[0])
	}
	// No label configured -> label falls back to the raw group name.
	if opts[1].Value != "planka-owners" || opts[1].Label != "planka-owners" {
		t.Errorf("unlabelled option should fall back to raw name: %+v", opts[1])
	}
}
