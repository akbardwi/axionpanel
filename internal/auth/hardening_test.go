package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestInternalErrorDoesNotBurnRecoveryCode(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	if r := c.post("login/mfa", `{"code":"000000"}`); r.code != 401 {
		t.Fatalf("seed failure = %d", r.code)
	}
	mustExec(t, e.s, `CREATE TRIGGER fail_throttle_delete BEFORE DELETE ON auth_throttle BEGIN SELECT RAISE(ABORT,'internal detail'); END`)
	r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0]))
	if r.code != 500 {
		t.Fatalf("internal failure = %d %s, want 500", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("internal error after consumption must roll back the recovery code")
	}
	if e.count(`SELECT count(*) FROM mfa_challenges`) != 1 {
		t.Fatal("internal error must not consume the challenge")
	}
}

func TestChallengesPerUserBounded(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.IPFailureLimit = 1000 })
	e.enroll(e.client("192.0.2.1:1"))
	for i := 0; i < 20; i++ {
		e.client(fmt.Sprintf("192.0.2.%d:1", 10+i)).login(t)
	}
	if n := e.count(`SELECT count(*) FROM mfa_challenges`); n > maxChallengesPerUser {
		t.Fatalf("challenges = %d, want <= %d", n, maxChallengesPerUser)
	}
}

func TestStaleThrottleRowsPruned(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.IPFailureLimit = 1000 })
	for i := 0; i < 10; i++ {
		e.client("192.0.2.9:1").post("login", fmt.Sprintf(`{"username":"ghost%d","password":"x"}`, i))
	}
	e.clock.advance(31 * time.Minute)
	e.client("192.0.2.9:1").post("login", `{"username":"ghost-new","password":"x"}`)
	if n := e.count(`SELECT count(*) FROM auth_throttle`); n > 2 {
		t.Fatalf("throttle rows after window = %d, want stale rows pruned", n)
	}
}
