package auth

import (
	"fmt"
	"net/http"
	"testing"
)

// The CSRF token must survive a page reload. The session cookie is HttpOnly,
// so the token is also issued as a readable axp_csrf cookie (double submit);
// the server still checks it against the hash stored with the session.
func TestCSRFCookieIssuedWithSession(t *testing.T) {
	check := func(t *testing.T, r resp) {
		t.Helper()
		ck := r.cookie(CSRFCookie)
		if ck == nil {
			t.Fatalf("no %s cookie in %v", CSRFCookie, r.cookies)
		}
		if ck.HttpOnly {
			t.Error("axp_csrf must be readable by the UI (not HttpOnly)")
		}
		if !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
			t.Errorf("cookie flags = %+v, want Secure, SameSite=Strict, Path=/", ck)
		}
		if ck.Value != r.body["csrf_token"] {
			t.Error("cookie value must equal the csrf_token in the body")
		}
	}

	t.Run("password login", func(t *testing.T) {
		e := newMFAEnv(t, true)
		check(t, e.client("192.0.2.1:1").login(t))
	})

	t.Run("mfa login sets it only after the second factor", func(t *testing.T) {
		e := newMFAEnv(t, true)
		c := e.client("192.0.2.1:1")
		sec, _ := e.enroll(c)
		c.post("logout", "")
		r := c.login(t)
		if r.cookie(CSRFCookie) != nil && r.cookie(CSRFCookie).MaxAge >= 0 {
			t.Error("challenge step must not issue a session CSRF cookie")
		}
		e.clock.advance(60e9)
		r = c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
		if r.code != 200 {
			t.Fatalf("login/mfa = %d %s", r.code, r.raw)
		}
		check(t, r)
	})

	t.Run("logout clears it", func(t *testing.T) {
		e := newMFAEnv(t, true)
		c := e.client("192.0.2.1:1")
		c.login(t)
		r := c.post("logout", "")
		ck := r.cookie(CSRFCookie)
		if r.code != 200 || ck == nil || ck.MaxAge >= 0 {
			t.Fatalf("logout = %d, csrf cookie %+v; want cleared", r.code, ck)
		}
	})

	t.Run("cookie alone does not satisfy CSRF", func(t *testing.T) {
		e := newMFAEnv(t, true)
		c := e.client("192.0.2.1:1")
		c.login(t)
		c.csrf = ""
		if r := c.post("logout", ""); r.code != 403 {
			t.Fatalf("logout without header = %d, want 403", r.code)
		}
	})
}
