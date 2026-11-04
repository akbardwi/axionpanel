package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAuditMFAEnrollmentAndDisable(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.8:1")
	sec, codes := e.enroll(c)
	for _, action := range []string{"auth.mfa.setup", "auth.mfa.enable", "auth.recovery_codes.generate"} {
		a := requireEvent(t, e, action, "success")
		if !a.User.Valid || a.Username.String != "admin" || a.IP != "192.0.2.8" {
			t.Fatalf("wrong actor %+v", a)
		}
	}
	if r := c.post("mfa/disable", `{}`); r.code != 200 {
		t.Fatalf("disable %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.mfa.disable", "success")
	noAuditSecrets(t, e, append(codes, sec, "sekret-1")...)
}
func TestAuditMFAMutationsRollback(t *testing.T) {
	for _, action := range []string{"auth.mfa.setup", "auth.mfa.enable", "auth.recovery_codes.generate", "auth.mfa.disable"} {
		t.Run(action, func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.8:1")
			c.login(t)
			if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 200 {
				t.Fatal(r)
			}
			var sec string
			if action != "auth.mfa.setup" {
				r := c.post("mfa/setup", `{}`)
				sec = r.body["secret"].(string)
			}
			if action == "auth.mfa.disable" {
				if r := c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 200 {
					t.Fatal(r)
				}
			}
			path, body := "mfa/setup", `{}`
			switch action {
			case "auth.mfa.enable", "auth.recovery_codes.generate":
				path = "mfa/enable"
				body = fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))
			case "auth.mfa.disable":
				path = "mfa/disable"
			}
			rejectAudit(t, e, action)
			before := len(auditRows(t, e))
			r := c.post(path, body)
			if r.code != 500 || strings.Contains(r.raw, "secret") || r.cookie(SessionCookie) != nil {
				t.Fatalf("audit fail %d %s", r.code, r.raw)
			}
			if len(auditRows(t, e)) != before {
				t.Fatal("partial audit persisted")
			}
			switch action {
			case "auth.mfa.setup":
				if e.count(`SELECT count(*) FROM users WHERE totp_pending_secret_enc IS NOT NULL`) != 0 {
					t.Fatal("pending secret persisted")
				}
			case "auth.mfa.enable", "auth.recovery_codes.generate":
				if e.count(`SELECT totp_enabled FROM users`) != 0 || e.count(`SELECT count(*) FROM user_recovery_codes`) != 0 {
					t.Fatal("MFA enable partially committed")
				}
			case "auth.mfa.disable":
				if e.count(`SELECT totp_enabled FROM users`) != 1 || e.count(`SELECT count(*) FROM user_recovery_codes`) != 10 {
					t.Fatal("MFA disable partially committed")
				}
			}
		})
	}
}
func TestAuditMFAChallengeAndFailure(t *testing.T) {
	e := newMFAEnv(t, true)
	e.enroll(e.client("192.0.2.8:1"))
	c := e.client("192.0.2.9:1")
	c.login(t)
	a := requireEvent(t, e, "auth.mfa.challenge", "success")
	if !a.User.Valid {
		t.Fatal("challenge missing actor")
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action='auth.login' AND outcome='success'`) != 1 {
		t.Fatal("password-only MFA login mislabeled full success")
	}
	rejectAudit(t, e, "auth.login.mfa")
	if r := c.post("login/mfa", `{"code":"wrong!"}`); r.code != 500 {
		t.Fatalf("failure audit rejected %d %s", r.code, r.raw)
	}
	if e.count(`SELECT attempts FROM mfa_challenges`) != 0 || e.count(`SELECT count(*) FROM auth_throttle WHERE scope='mfa_user'`) != 0 {
		t.Fatal("unaudited failed factor mutated state")
	}
	mustExec(t, e.s, `DROP TRIGGER reject_audit`)
	if r := c.post("login/mfa", `{"code":"wrong!"}`); r.code != 401 {
		t.Fatalf("factor failure %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.login.mfa", "failure")
	if e.count(`SELECT attempts FROM mfa_challenges`) != 1 {
		t.Fatal("attempt not burned")
	}
}
func TestAuditMFARecoveryRollbackAndUse(t *testing.T) {
	for _, action := range []string{"auth.login.mfa", "auth.recovery_code.use"} {
		t.Run(action, func(t *testing.T) {
			e := newMFAEnv(t, true)
			_, codes := e.enroll(e.client("192.0.2.8:1"))
			c := e.client("192.0.2.9:1")
			c.login(t)
			rejectAudit(t, e, action)
			r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0]))
			if r.code != 500 || r.cookie(SessionCookie) != nil || r.cookie(CSRFCookie) != nil || strings.Contains(r.raw, "audit private") {
				t.Fatalf("MFA audit fail %d %s", r.code, r.raw)
			}
			if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM mfa_challenges`) != 1 || e.count(`SELECT count(*) FROM sessions WHERE ip='192.0.2.9'`) != 0 {
				t.Fatal("recovery or challenge consumed/session granted")
			}
			mustExec(t, e.s, `DROP TRIGGER reject_audit`)
			if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 200 {
				t.Fatal(r)
			}
			requireEvent(t, e, "auth.recovery_code.use", "success")
			requireEvent(t, e, "auth.login.mfa", "success")
			noAuditSecrets(t, e, codes[0], normalizeRecovery(codes[0]), hashToken(normalizeRecovery(codes[0])))
		})
	}
}
func TestAuditReauthFailureAndFactorRollback(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.8:1")
	_, codes := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	if r := c.post("reauth", `{"password":"wrong-private"}`); r.code != 403 {
		t.Fatal(r)
	}
	requireEvent(t, e, "auth.reauth", "failure")
	rejectAudit(t, e, "auth.reauth")
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0])); r.code != 500 {
		t.Fatalf("reauth factor audit %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM sessions WHERE sudo_until>?`, fmtTime(e.clock.now)) != 0 {
		t.Fatal("reauth factor consumed or sudo granted")
	}
	noAuditSecrets(t, e, "wrong-private", codes[0])
}
func TestAuditLoginFailureDoesNotChangeLastLogin(t *testing.T) {
	e := newMFAEnv(t, true)
	rejectAudit(t, e, "auth.login")
	r := e.client("192.0.2.8:1").post("login", `{"username":"admin","password":"sekret-1"}`)
	if r.code != 500 {
		t.Fatal(r)
	}
	if e.count(`SELECT count(*) FROM users WHERE last_login_at IS NOT NULL`) != 0 {
		t.Fatal("failed audit changed last_login_at")
	}
}
