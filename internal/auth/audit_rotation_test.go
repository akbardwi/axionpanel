package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditPasswordChangeRevalidatesExpiryUnderLock(t *testing.T) {
	for _, kind := range []string{"idle", "absolute"} {
		t.Run(kind, func(t *testing.T) {
			e := newMFAEnv(t, false)
			c := e.client("192.0.2.8:1")
			c.login(t)
			c.post("reauth", `{"password":"sekret-1"}`)
			req := httptest.NewRequest("POST", "/api/v1/auth/password", strings.NewReader(`{"new_password":"replacement-private"}`))
			req.AddCookie(c.cookies[SessionCookie])
			req.Header.Set("X-CSRF-Token", c.csrf)
			rec := httptest.NewRecorder()
			e.s.requireAuth(e.s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sess := sessionFrom(r.Context())
				if kind == "idle" {
					mustExec(t, e.s, `UPDATE sessions SET last_seen_at=? WHERE id=?`, fmtTime(e.clock.now.Add(-e.s.cfg.SessionIdleTTL)), sess.ID)
				} else {
					mustExec(t, e.s, `UPDATE sessions SET expires_at=? WHERE id=?`, fmtTime(e.clock.now), sess.ID)
				}
				e.s.handlePassword(w, r)
			}))).ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Fatalf("expired rotation=%d %s", rec.Code, rec.Body)
			}
			if e.count(`SELECT count(*) FROM audit_log WHERE action='auth.password.change'`) != 0 {
				t.Fatal("expired session changed password")
			}
		})
	}
}
func TestAuditStalePasswordCannotBeAcceptedAfterRotation(t *testing.T) {
	e := newMFAEnv(t, true)
	ctx := context.Background()
	u, err := e.s.verifyPassword(ctx, "admin", "sekret-1", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := HashPassword("replacement-private")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, e.s, `UPDATE users SET password_hash=? WHERE id=?`, replacement, u.ID)
	tx, err := e.s.writeTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = e.s.passwordAccepted(ctx, tx, u, "192.0.2.8", true); err != ErrInvalidCredentials {
		t.Fatalf("stale password accepted: %v", err)
	}
}
func TestAuditReauthRecoveryFailureMethod(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.8:1")
	e.enroll(c)
	e.clock.advance(11 * time.Minute)
	r := c.post("reauth", `{"password":"sekret-1","recovery_code":"wrong-private-recovery"}`)
	if r.code != 403 {
		t.Fatal(r)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth' AND outcome='failure' AND json_extract(details,'$.method')='recovery_code'`) != 1 {
		t.Fatal("wrong recovery factor mislabeled")
	}
}
func TestAuditMFAIPLockoutDurable(t *testing.T) {
	e := newMFAEnv(t, true)
	e.enroll(e.client("192.0.2.8:1"))
	c := e.client("192.0.2.9:1")
	c.login(t)
	mustExec(t, e.s, `UPDATE auth_throttle SET failures=? WHERE scope='ip'`, e.s.cfg.IPFailureLimit)
	r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, "wrong!"))
	if r.code != 429 {
		t.Fatalf("ip lockout=%d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.login.mfa", "denied")
}
