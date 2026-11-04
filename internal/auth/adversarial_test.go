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

func TestEnableFailureThrottle(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	sec := c.post("mfa/setup", `{}`).body["secret"].(string)
	for i := 0; i < 5; i++ {
		r := c.post("mfa/enable", `{"code":"wrong!"}`)
		if r.code != 422 {
			t.Fatalf("failure %d: %d %s", i, r.code, r.raw)
		}
	}
	r := c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
	if r.code != 423 {
		t.Fatalf("enable after failures = %d %s, want 423", r.code, r.raw)
	}
}

func TestPendingEnrollmentCanRestart(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	a := c.post("mfa/setup", `{}`)
	b := c.post("mfa/setup", `{}`)
	if a.code != 200 || b.code != 200 || a.body["secret"] == b.body["secret"] {
		t.Fatalf("restart setup: %d %d", a.code, b.code)
	}
	if r := c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(a.body["secret"].(string), e.clock.now))); r.code != 422 {
		t.Fatalf("old pending code = %d", r.code)
	}
}

func TestDisableRequiresSecretBox(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	e.enroll(c)
	e.s.WithSecretBox(nil)
	if r := c.post("mfa/disable", `{}`); r.code != 503 {
		t.Fatalf("disable without box = %d", r.code)
	}
}

func TestMFAAtomicRollbackOnSessionFailure(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	mustExec(t, e.s, `CREATE TRIGGER reject_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'secret database detail'); END`)
	r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0]))
	if r.code != 500 || strings.Contains(r.raw, "secret database") {
		t.Fatalf("failure = %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM mfa_challenges`) != 1 {
		t.Fatal("failed session insert consumed challenge or code")
	}
	mustExec(t, e.s, `DROP TRIGGER reject_session`)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 200 {
		t.Fatalf("retry = %d %s", r.code, r.raw)
	}
}

func TestDisableAtomicRollback(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	e.enroll(c)
	mustExec(t, e.s, `CREATE TRIGGER reject_recovery_delete BEFORE DELETE ON user_recovery_codes BEGIN SELECT RAISE(ABORT,'hidden detail'); END`)
	if r := c.post("mfa/disable", `{}`); r.code != 500 {
		t.Fatalf("disable = %d", r.code)
	}
	if e.count(`SELECT count(*) FROM users WHERE totp_enabled=1`) != 1 || e.count(`SELECT count(*) FROM user_recovery_codes`) != 10 {
		t.Fatal("disable not atomic")
	}
}

func TestChallengeSurvivesServiceRestart(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	s := New(e.db, e.s.cfg, e.clock).WithSecretBox(e.s.box)
	e.mux = http.NewServeMux()
	s.Register(e.mux)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 200 {
		t.Fatalf("restart lost challenge: %d %s", r.code, r.raw)
	}
}

func TestChallengeExpiresAtExactDeadline(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	e.clock.advance(5 * time.Minute)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 401 {
		t.Fatalf("exact expiry accepted: %d", r.code)
	}
}

func TestIPv6IPParsingAndThrottle(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "[2001:db8:abcd::1]:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := peerIP(r); got != "2001:db8:abcd::1" {
		t.Fatalf("IP = %q", got)
	}
	e := newMFAEnv(t, true, func(c *Config) { c.IPFailureLimit = 2 })
	for i := 1; i <= 2; i++ {
		e.client(fmt.Sprintf("[2001:db8:abcd::%d]:1", i)).post("login", fmt.Sprintf(`{"username":"ghost%d","password":"x"}`, i))
	}
	if r := e.client("[2001:db8:abcd::ff]:1").post("login", `{"username":"admin","password":"sekret-1"}`); r.code != 429 {
		t.Fatalf("IPv6 /64 throttle = %d", r.code)
	}
}

func TestMFAReauthRateLimit(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	sec, _ := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	for i := 0; i < 5; i++ {
		r := c.post("reauth", `{"password":"sekret-1","code":"wrong!"}`)
		if r.code != 403 {
			t.Fatalf("failure %d = %d", i, r.code)
		}
	}
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 423 {
		t.Fatalf("locked reauth = %d %s", r.code, r.raw)
	}
}

func TestMFACodeReplayAcrossServices(t *testing.T) {
	e := newMFAEnv(t, true)
	sec, _ := e.enroll(e.client("192.0.2.1:1"))
	e.clock.advance(30 * time.Second)
	a := e.client("192.0.2.2:1")
	b := e.client("192.0.2.3:1")
	a.login(t)
	b.login(t)
	body := fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))
	if r := a.post("login/mfa", body); r.code != 200 {
		t.Fatalf("first = %d", r.code)
	}
	s := New(e.db, e.s.cfg, e.clock).WithSecretBox(e.s.box)
	e.mux = http.NewServeMux()
	s.Register(e.mux)
	if r := b.post("login/mfa", body); r.code != 401 {
		t.Fatalf("replay after service restart = %d", r.code)
	}
}

func TestMissingBoxRecoveryFailsClosed(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	e.s.WithSecretBox(nil)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 503 {
		t.Fatalf("missing box recovery = %d", r.code)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("code consumed without box")
	}
}

func TestPHCAndPasswordBounds(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("x", 1025)); err == nil {
		t.Fatal("long HashPassword accepted")
	}
	if VerifyPassword(dummyHash, strings.Repeat("x", 1025)) {
		t.Fatal("long verification accepted")
	}
	for _, hash := range []string{strings.Repeat("x", 513), "argon2id$v=19$m=19456,t=2,p=1$YQ$YQ", strings.Replace(dummyHash, "v=19", "v=18", 1)} {
		if VerifyPassword(hash, "pw") {
			t.Fatal("invalid hash accepted")
		}
	}
}

func TestSessionStatusRecheckedAtSudoMutation(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	cookie := c.cookies[SessionCookie]
	sess, err := e.s.Lookup(context.Background(), hashToken(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, e.s, `UPDATE users SET status='suspended'`)
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/setup", strings.NewReader(`{}`))
	req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey, sess))
	w := httptest.NewRecorder()
	e.s.handleSetup(w, req)
	if w.Code != 401 {
		t.Fatalf("stale authenticated context accepted: %d %s", w.Code, w.Body)
	}
}
