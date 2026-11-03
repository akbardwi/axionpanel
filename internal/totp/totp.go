// Package totp implements RFC 6238 time-based one-time passwords (HMAC-SHA1,
// the variant every common authenticator app supports).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Params selects the code shape. Authenticator apps assume Default.
type Params struct {
	Period int64 // seconds per step
	Digits int
}

// Default is the 30-second, 6-digit profile used by authenticator apps.
var Default = Params{Period: 30, Digits: 6}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a random 160-bit secret, base32 without padding.
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp: secret: %w", err)
	}
	return b32.EncodeToString(buf), nil
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "="))
	key, err := b32.DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("totp: invalid secret")
	}
	return key, nil
}

// Code returns the code for the step containing t.
func Code(secret string, t time.Time, p Params) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return codeAt(key, t.Unix()/p.Period, p.Digits), nil
}

func codeAt(key []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Verify reports whether code matches any step within ±window of t. The
// comparison is constant-time per candidate.
func Verify(secret, code string, t time.Time, p Params, window int) bool {
	_, ok := Match(secret, code, t, p, window)
	return ok
}

// Match is Verify plus the step counter the code belongs to, so callers can
// persist it and reject replays of the same code.
func Match(secret, code string, t time.Time, p Params, window int) (int64, bool) {
	if len(code) != p.Digits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	counter := t.Unix() / p.Period
	var matched int64
	ok := 0
	for d := -window; d <= window; d++ {
		if subtle.ConstantTimeCompare([]byte(codeAt(key, counter+int64(d), p.Digits)), []byte(code)) == 1 {
			matched = counter + int64(d)
			ok = 1
		}
	}
	return matched, ok == 1
}

// OTPAuthURL builds the provisioning URI that authenticator apps scan.
func OTPAuthURL(issuer, account, secret string, p Params) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("digits", fmt.Sprint(p.Digits))
	q.Set("period", fmt.Sprint(p.Period))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}
