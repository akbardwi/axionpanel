package auth

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestAuditReauthSecondFactorVerdicts(t *testing.T) {
	for _, kind := range []string{"missing", "wrong", "locked", "recovery"} {
		t.Run(kind, func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.8:1")
			_, codes := e.enroll(c)
			e.clock.advance(11 * time.Minute)
			body := `{"password":"sekret-1"}`
			outcome := "denied"
			method := "totp"
			want := 403
			switch kind {
			case "wrong":
				body = `{"password":"sekret-1","code":"wrong!"}`
				outcome = "failure"
			case "locked":
				body = `{"password":"sekret-1","code":"wrong!"}`
				mustExec(t, e.s, `INSERT INTO auth_throttle(scope,key,failures,window_start) VALUES('mfa_user',?,5,?)`, mfaKey(1), fmtTime(e.clock.now))
				want = 423
			case "recovery":
				body = fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0])
				outcome = "success"
				method = "recovery_code"
				want = 200
			}
			before := e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth'`)
			r := c.post("reauth", body)
			if r.code != want {
				t.Fatalf("verdict %d %s", r.code, r.raw)
			}
			if n := e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth'`); n != before+1 {
				t.Fatalf("reauth events %d want %d", n, before+1)
			}
			if n := e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth' AND outcome=? AND json_extract(details,'$.method')=?`, outcome, method); n != 1 {
				t.Fatal("wrong factor outcome/method")
			}
			if kind == "recovery" {
				requireEvent(t, e, "auth.recovery_code.use", "success")
			}
		})
	}
}
func TestAuditMFAEnrollmentFailure(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.8:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	c.post("mfa/setup", `{}`)
	rejectAudit(t, e, "auth.mfa.enable")
	if r := c.post("mfa/enable", `{"code":"wrong!"}`); r.code != 500 {
		t.Fatalf("enrollment failure not durable %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM auth_throttle WHERE scope='mfa_user'`) != 0 {
		t.Fatal("unaudited guess burned budget")
	}
	mustExec(t, e.s, `DROP TRIGGER reject_audit`)
	if r := c.post("mfa/enable", `{"code":"wrong!"}`); r.code != 422 {
		t.Fatal(r)
	}
	requireEvent(t, e, "auth.mfa.enable", "failure")
}
func TestAuditTrustedProxyActor(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			e := newMFAEnv(t, true, func(c *Config) {
				if trusted {
					c.TrustedProxies, _ = ParseTrustedProxies([]string{"127.0.0.0/8"})
				}
			})
			r := e.client("127.0.0.1:333").do("POST", "login", `{"username":"admin","password":"sekret-1"}`, map[string]string{"CF-Connecting-IP": "203.0.113.8", "X-Actor-ID": "999", "X-Username": "forged"})
			if r.code != 200 {
				t.Fatal(r)
			}
			a := requireEvent(t, e, "auth.login", "success")
			ip := "127.0.0.1"
			if trusted {
				ip = "203.0.113.8"
			}
			if a.IP != ip || a.User.Int64 != 1 || a.Username.String != "admin" {
				t.Fatalf("spoofed %+v", a)
			}
		})
	}
}
func TestAuditChallengeFailureDoesNotGrantIntermediateCredential(t *testing.T) {
	e := newMFAEnv(t, true)
	e.enroll(e.client("192.0.2.8:1"))
	rejectAudit(t, e, "auth.mfa.challenge")
	r := e.client("192.0.2.9:1").post("login", `{"username":"admin","password":"sekret-1"}`)
	if r.code != 500 || len(r.cookies) != 0 || e.count(`SELECT count(*) FROM mfa_challenges`) != 0 {
		t.Fatalf("challenge leaked %d %s", r.code, r.raw)
	}
}
func TestAuditSessionCreationFailsClosed(t *testing.T) {
	e := newMFAEnv(t, true)
	rejectAudit(t, e, "auth.session.create")
	sess, err := e.s.CreateSession(context.Background(), 1, "192.0.2.8", "private-user-agent")
	if err == nil || sess != nil || e.count(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("service session created without audit")
	}
}
func TestAuditPasswordRotationRevokesPendingMFA(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.8:1")
	_, codes := e.enroll(c)
	pending := e.client("192.0.2.9:1")
	pending.login(t)
	if r := c.post("password", `{"new_password":"new-private"}`); r.code != 200 {
		t.Fatal(r)
	}
	if e.count(`SELECT count(*) FROM mfa_challenges`) != 0 {
		t.Fatal("old password challenge survived rotation")
	}
	if r := pending.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 401 {
		t.Fatalf("old password granted credential %d", r.code)
	}
}
