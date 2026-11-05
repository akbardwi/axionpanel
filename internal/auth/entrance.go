package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The secret entrance grants discovery only: it never creates a session,
// CSRF token, sudo grant or MFA pass. The cookie is a domain-separated HMAC
// derivative of the path, so the raw path is never stored in the browser and
// the 24h lifetime is enforced server-side from the signed timestamp.
const (
	EntranceCookie = "axp_entrance"
	entranceTTL    = 24 * time.Hour
	// entranceDomain separates this key from every other use of the path.
	entranceDomain = "axionpanel/entrance/v1"
)

var ErrInvalidEntrancePath = errors.New("auth: entrance path must be slash plus 12 base64url characters")

// ValidateEntrancePath accepts an empty path (gate disabled) or exactly one
// slash followed by 12 ASCII base64url characters. The error never echoes the
// supplied value so a bad configuration cannot be logged with its secret.
func ValidateEntrancePath(path string) error {
	if path == "" {
		return nil
	}
	if len(path) != 13 || path[0] != '/' {
		return ErrInvalidEntrancePath
	}
	for i := 1; i < len(path); i++ {
		c := path[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return ErrInvalidEntrancePath
	}
	return nil
}

// entranceKey is the non-reversible, domain-separated SHA-256 derivative of the
// secret path. It is the HMAC key for that path; neither the digest nor any
// cookie derived from it reveals the path.
func entranceKey(path string) []byte {
	sum := sha256.Sum256([]byte(entranceDomain + "\x00" + path))
	return sum[:]
}

// Entrance validates the optional path at initialization and builds the gate.
// An empty path disables gating and returns next unchanged.
func (s *Service) Entrance(path string, next http.Handler) (http.Handler, error) {
	if err := ValidateEntrancePath(path); err != nil {
		return nil, err
	}
	if path == "" {
		return next, nil
	}
	if next == nil {
		return nil, errors.New("auth: entrance requires a handler")
	}
	key := entranceKey(path)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			// A non-GET secret path is indistinguishable from any other miss
			// and never mints a cookie, authenticated session or not.
			if r.URL.Path == path {
				entranceDeny(w)
				return
			}
			if s.entranceAdmitted(r, key) {
				next.ServeHTTP(w, r)
				return
			}
			entranceDeny(w)
			return
		}
		if r.URL.Path == path {
			if exactEntrancePath(r, path) {
				s.setEntranceCookie(w, key)
			} else {
				entranceDeny(w)
			}
			return
		}
		if s.entranceAdmitted(r, key) {
			next.ServeHTTP(w, r)
			return
		}
		entranceDeny(w)
	}), nil
}

// exactEntrancePath requires the literal request path: no query, no force-query
// and no percent-encoding alias such as /%41bc... that decodes to the secret.
func exactEntrancePath(r *http.Request, path string) bool {
	return r.URL.Path == path && r.URL.RawPath == "" && r.URL.RawQuery == "" &&
		!r.URL.ForceQuery && r.URL.EscapedPath() == path
}

// entranceAdmitted is discovery only: a valid entrance cookie or a genuine
// authenticated session verified through Lookup. Lookup rejects forged,
// expired and MFA-incomplete sessions, so the cookie alone proves nothing.
func (s *Service) entranceAdmitted(r *http.Request, key []byte) bool {
	if s.validEntranceCookie(r, key) {
		return true
	}
	if countCookies(r, SessionCookie) != 1 {
		return false
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return false
	}
	_, err = s.Lookup(r.Context(), hashToken(c.Value))
	return err == nil
}

// validEntranceCookie fails closed on missing, duplicated, malformed, tampered
// or expired cookies. The signature covers the issue timestamp, so editing
// the cookie cannot extend its 24h lifetime.
func (s *Service) validEntranceCookie(r *http.Request, key []byte) bool {
	now := s.now.Now()
	if countCookies(r, EntranceCookie) != 1 {
		return false
	}
	c, err := r.Cookie(EntranceCookie)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw[:8])
	if subtle.ConstantTimeCompare(mac.Sum(nil), raw[8:]) != 1 {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0).UTC()
	if issued.After(now) || !now.Before(issued.Add(entranceTTL)) {
		return false
	}
	return true
}

// countCookies counts raw Cookie-header pairs, including malformed duplicates
// that r.Cookies() would silently drop.
func countCookies(r *http.Request, name string) int {
	n := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			namePart, _, ok := strings.Cut(part, "=")
			if ok && strings.TrimSpace(namePart) == name {
				n++
			}
		}
	}
	return n
}

// setEntranceCookie mints the redirect response and its discovery cookie. The
// response carries no secret path in Location or body.
func (s *Service) setEntranceCookie(w http.ResponseWriter, key []byte) {
	now := s.now.Now().UTC().Truncate(time.Second)
	raw := make([]byte, 8+sha256.Size)
	binary.BigEndian.PutUint64(raw[:8], uint64(now.Unix()))
	mac := hmac.New(sha256.New, key)
	mac.Write(raw[:8])
	copy(raw[8:], mac.Sum(nil))
	s.setCookie(w, EntranceCookie, base64.RawURLEncoding.EncodeToString(raw), now.Add(entranceTTL), int(entranceTTL/time.Second))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Location", "/login")
	w.WriteHeader(http.StatusSeeOther)
}

// entranceDeny mirrors an ordinary missing route. It sets no cookie and leaks
// the secret path. Network/TLS fingerprints remain outside this gate.
func entranceDeny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not Found\n"))
}
