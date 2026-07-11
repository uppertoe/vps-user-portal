// Package audit records every portal mutation: a structured line to stdout
// (collected by the container log pipeline) and, when configured, a push to
// an ntfy topic so admins see account changes as they happen.
//
// Audit lines identify WHO (the acting admin, from the authenticated
// Remote-User header), WHAT (action, target user, groups) and the outcome.
// They never contain hashes, DSNs or credentials.
package audit

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Logger struct {
	// NtfyURL is a full topic URL (https://ntfy.example.org/topic); empty
	// disables push notifications.
	NtfyURL string
	// Client for ntfy posts; defaults are fine outside tests.
	Client *http.Client
}

// Event records one mutation attempt.
func (l *Logger) Event(actor, action, target string, detail string, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error: " + err.Error()
	}
	slog.Info("audit",
		"actor", actor,
		"action", action,
		"target", target,
		"detail", detail,
		"outcome", outcome,
	)
	if l.NtfyURL == "" {
		return
	}
	title := fmt.Sprintf("user-portal: %s %s", action, target)
	body := fmt.Sprintf("by %s — %s (%s)", actor, detail, outcome)
	go l.notify(title, body, err != nil)
}

func (l *Logger) notify(title, body string, failed bool) {
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, l.NtfyURL, strings.NewReader(body))
	if err != nil {
		slog.Warn("ntfy notify failed", "err", err)
		return
	}
	req.Header.Set("Title", title)
	if failed {
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "warning")
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("ntfy notify failed", "err", err)
		return
	}
	resp.Body.Close()
}
