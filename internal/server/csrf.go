package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CSRF tokens are stateless: HMAC(secret, expiry|actor), bound to the
// authenticated admin (Remote-User) so a token minted for one admin is
// useless in another's form. The portal has no cookies or sessions of its
// own — identity comes per-request from the forward-auth gateway — so
// double-submit patterns don't apply; an HMAC field is the right shape.

const csrfTTL = 4 * time.Hour

func csrfMAC(secret []byte, exp int64, actor string) []byte {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d|%s", exp, actor)
	return mac.Sum(nil)
}

func csrfToken(secret []byte, actor string, now time.Time) string {
	exp := now.Add(csrfTTL).Unix()
	sig := csrfMAC(secret, exp, actor)
	return fmt.Sprintf("%d.%s", exp, base64.RawURLEncoding.EncodeToString(sig))
}

func csrfValid(secret []byte, actor, token string, now time.Time) bool {
	expStr, sigStr, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() > exp {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return false
	}
	return hmac.Equal(sig, csrfMAC(secret, exp, actor))
}
