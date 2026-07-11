package server

import (
	"testing"
	"time"
)

func TestCSRFRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now()
	tok := csrfToken(secret, "admin@example.org", now)

	if !csrfValid(secret, "admin@example.org", tok, now) {
		t.Error("fresh token rejected")
	}
	if csrfValid(secret, "other@example.org", tok, now) {
		t.Error("token accepted for a different actor")
	}
	if csrfValid(secret, "admin@example.org", tok, now.Add(csrfTTL+time.Minute)) {
		t.Error("expired token accepted")
	}
	if csrfValid([]byte("another-secret-another-secret-32"), "admin@example.org", tok, now) {
		t.Error("token accepted under a different secret")
	}
	if csrfValid(secret, "admin@example.org", tok+"x", now) {
		t.Error("tampered token accepted")
	}
	if csrfValid(secret, "admin@example.org", "garbage", now) {
		t.Error("garbage token accepted")
	}
}
