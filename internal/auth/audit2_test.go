package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuditLogoutAtomic(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.9:1")
	c.login(t)
	rejectAudit(t, e, "auth.logout")
	r := c.post("logout", `{}`)
	if r.code != 500 || strings.Contains(r.raw, "audit private") {
		t.Fatalf("logout audit fail %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM sessions`) != 1 {
		t.Fatal("session deleted without audit")
	}
	mustExec(t, e.s, `DROP TRIGGER reject_audit`)
	if r := c.post("logout", `{}`); r.code != 200 {
		t.Fatalf("retry %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.logout", "success")
	if e.count(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("logout did not delete session")
	}
}
func TestAuditMFAFactorNoLeak(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.9:1")
	sec, codes := e.enroll(c)
	e.clock.advance(time.Minute)
	// enroll already emits events; capture baseline count
	baseline := len(auditRows(t, e))
	c2 := e.client("192.0.2.10:2")
	c2.login(t)
	if r := c2.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 200 {
		t.Fatalf("mfa %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.login.mfa", "success")
	noAuditSecrets(t, e, codes[0], sec, e.codeAt(sec, e.clock.now), c2.cookies[SessionCookie].Value, c2.csrf)
	if len(auditRows(t, e)) != baseline+2 {
		t.Fatalf("unexpected events: %+v", auditRows(t, e))
	}
}
func TestAuditReauthFailClosed(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.9:1")
	c.login(t)
	rejectAudit(t, e, "auth.reauth")
	r := c.post("reauth", `{"password":"sekret-1"}`)
	if r.code != 500 || strings.Contains(r.raw, "audit private") {
		t.Fatalf("reauth audit fail %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`) != 0 {
		t.Fatal("sudo granted without audit")
	}
	mustExec(t, e.s, `DROP TRIGGER reject_audit`)
	if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 200 {
		t.Fatalf("retry %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.reauth", "success")
}
func TestAuditConcurrentAppends(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.IPFailureLimit = 10000 })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e.client(fmt.Sprintf("192.0.2.%d:%d", 1+i%250, i)).post("login", fmt.Sprintf(`{"username":"ghost%d","password":"x"}`, i))
		}(i)
	}
	wg.Wait()
	if n := e.count(`SELECT count(*) FROM audit_log`); n != 16 {
		t.Fatalf("events=%d want 16", n)
	}
}
