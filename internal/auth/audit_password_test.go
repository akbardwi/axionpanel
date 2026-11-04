package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAuditPasswordChangeAtomicAndRevokesCredentials(t *testing.T) {
	for _, withBox := range []bool{false, true} {
		t.Run(fmt.Sprint(withBox), func(t *testing.T) {
			e := newMFAEnv(t, withBox)
			c := e.client("192.0.2.8:1")
			c.login(t)
			other := e.client("192.0.2.9:1")
			other.login(t)
			if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 200 {
				t.Fatal(r)
			}
			rejectAudit(t, e, "auth.password.change")
			r := c.post("password", `{"new_password":"new-private-password"}`)
			if r.code != 500 || strings.Contains(r.raw, "audit private") || r.cookie(SessionCookie) != nil {
				t.Fatalf("change not fail closed %d %s", r.code, r.raw)
			}
			var hash string
			if err := e.db.QueryRow(`SELECT password_hash FROM users`).Scan(&hash); err != nil {
				t.Fatal(err)
			}
			if !VerifyPassword(hash, "sekret-1") || e.count(`SELECT count(*) FROM sessions`) != 2 {
				t.Fatal("failed audit changed password/sessions")
			}
			mustExec(t, e.s, `DROP TRIGGER reject_audit`)
			r = c.post("password", `{"new_password":"new-private-password"}`)
			if r.code != 200 {
				t.Fatalf("change %d %s", r.code, r.raw)
			}
			a := requireEvent(t, e, "auth.password.change", "success")
			if a.Username.String != "admin" || a.IP != "192.0.2.8" {
				t.Fatalf("actor %+v", a)
			}
			if e.count(`SELECT count(*) FROM sessions`) != 0 {
				t.Fatal("password change kept sessions")
			}
			if r := other.do("GET", "me", "", nil); r.code != 401 {
				t.Fatal("old session retained")
			}
			if r := e.client("192.0.2.10:1").post("login", `{"username":"admin","password":"new-private-password"}`); r.code != 200 {
				t.Fatal(r)
			}
			noAuditSecrets(t, e, "new-private-password", hash, hashToken(c.csrf))
		})
	}
}
func TestAuditPasswordChangeRequiresCSRFAndFreshSudo(t *testing.T) {
	e := newMFAEnv(t, false)
	c := e.client("192.0.2.8:1")
	c.login(t)
	if r := c.post("password", `{"new_password":"new-private-password"}`); r.code != 403 {
		t.Fatalf("no sudo %d %s", r.code, r.raw)
	}
	if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 200 {
		t.Fatal(r)
	}
	if r := c.do("POST", "password", `{"new_password":"new-private-password"}`, map[string]string{"X-CSRF-Token": "wrong"}); r.code != 403 {
		t.Fatalf("no csrf %d %s", r.code, r.raw)
	}
	e.clock.advance(11 * time.Minute)
	if r := c.post("password", `{"new_password":"new-private-password"}`); r.code != 403 {
		t.Fatalf("expired sudo %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action='auth.password.change'`) != 0 {
		t.Fatal("denied mutation emitted success")
	}
}
