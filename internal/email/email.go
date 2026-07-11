// Package email sends the invite welcome mail.
//
// The welcome mail deliberately carries NO secret and NO one-time link — the
// recipient is told to visit the SSO portal and use "Reset password?"
// themselves. That makes the mail immune to link-detonating scanners
// (Microsoft Defender Safe Links renders links and runs their JS on
// delivery, consuming one-time tokens before the user can click); the
// password-reset flow it points at has its own defences.
package email

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Sender delivers a welcome mail to a newly invited user.
type Sender interface {
	SendWelcome(to, displayName, ssoURL string) error
}

// --- SMTP (STARTTLS submission, e.g. AWS SES on :587) ---

type SMTP struct {
	Host, Port, Username, Password, From, SubjectPrefix string
}

func (s *SMTP) SendWelcome(to, displayName, ssoURL string) error {
	subject := fmt.Sprintf("%s Your account is ready", s.SubjectPrefix)
	body := welcomeBody(displayName, to, ssoURL)
	msg := strings.Join([]string{
		"From: " + s.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")
	addr := s.Host + ":" + s.Port
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	// net/smtp upgrades to STARTTLS automatically when the server offers it
	// and refuses to send AUTH over plaintext, which is the right failure.
	if err := smtp.SendMail(addr, auth, s.From, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("send welcome mail: %w", err)
	}
	return nil
}

// --- Log backend (local testing: prints instead of sending) ---

type Log struct{}

func (Log) SendWelcome(to, displayName, ssoURL string) error {
	slog.Info("welcome mail (log backend)", "to", to, "body", welcomeBody(displayName, to, ssoURL))
	return nil
}

// --- None backend (portal shows the instructions to the admin instead) ---

type None struct{}

func (None) SendWelcome(string, string, string) error { return nil }

func welcomeBody(displayName, email, ssoURL string) string {
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = email
	}
	return fmt.Sprintf(`Hello %s,

An account has been created for you (%s).

To get started, set your password:

  1. Go to %s
  2. Click "Reset password?"
  3. Enter your email address and follow the emailed instructions.

Once your password is set, sign in at the same address.

If you weren't expecting this account, you can ignore this email — the
account cannot be used until you set a password.
`, name, email, ssoURL)
}

// Instructions returns the same steps as text for the admin UI, used when
// mail delivery is disabled or fails so the admin can forward them manually.
func Instructions(email, ssoURL string) string {
	return fmt.Sprintf("Account created for %s. To activate: go to %s, click \"Reset password?\", enter this email address and follow the emailed instructions.", email, ssoURL)
}
