package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestAuditTOTPStepRollbackOnInsertFailure(t *testing.T) {
	e := newMFAEnv(t, true)
	sec, _ := e.enroll(e.client("192.0.2.8:1"))
	e.clock.advance(time.Minute)
	c := e.client("192.0.2.9:1")
	c.login(t)
	rejectAudit(t, e, "auth.login.mfa")
	step := e.clock.now.Unix() / 30
	r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
	if r.code != 500 || r.cookie(SessionCookie) != nil || e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, step) != 0 || e.count(`SELECT attempts FROM mfa_challenges`) != 0 {
		t.Fatalf("TOTP audit rollback failed %d %s", r.code, r.raw)
	}
	mustExec(t, e.s, `DROP TRIGGER reject_audit`)
	if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 200 {
		t.Fatal(r)
	}
	if e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, step) != 1 {
		t.Fatal("TOTP retry not consumed")
	}
}
func TestAuditChallengeRevalidatesActiveMFAUnderLock(t *testing.T) {
	for _, kind := range []string{"disabled", "suspended"} {
		t.Run(kind, func(t *testing.T) {
			e := newMFAEnv(t, true)
			e.enroll(e.client("192.0.2.8:1"))
			// Fix the interleaving after verifyPassword reserves its attempt and reads
			// the user, but before challenge creation begins its transaction.
			mustExec(t, e.s, `CREATE TRIGGER change_on_reservation AFTER UPDATE OF failed_logins ON users WHEN NEW.failed_logins>0 BEGIN UPDATE users SET `+map[string]string{"disabled": "totp_enabled=0", "suspended": "status='suspended'"}[kind]+` WHERE id=NEW.id; END`)
			c := e.client("192.0.2.9:1")
			r := c.post("login", `{"username":"admin","password":"sekret-1"}`)
			if r.code != 401 || r.cookie(MFACookie) != nil || e.count(`SELECT count(*) FROM mfa_challenges`) != 0 {
				t.Fatalf("stale challenge granted %d %s", r.code, r.raw)
			}
		})
	}
}
