package userstore

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters matching the estate's Authelia configuration
// (authentication_backend.file.password). Authelia validates stored digests
// by the parameters embedded in the PHC string, so these only need to be
// sane — but matching the config keeps the file uniform.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ThrowawayHash returns a valid argon2id PHC digest of a random password
// that is immediately discarded. The resulting account cannot be logged into
// until its owner completes Authelia's self-service password reset — which
// is the invite flow's email-verification step.
func ThrowawayHash() (string, error) {
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return "", fmt.Errorf("random password: %w", err)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("random salt: %w", err)
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64(salt), b64(key)), nil
}
