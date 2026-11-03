package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestReauthInternalFactorErrorsRollback(t *testing.T) {
	for _, kind := range []string{"corrupt_secret", "totp_write", "recovery_write"} {
		t.Run(kind, func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.1:1")
			sec, codes := e.enroll(c)
			e.clock.advance(11 * time.Minute)
			// Legitimate rejection still consumes exactly one failure.
			if r := c.post("reauth", `{"password":"sekret-1","code":"wrong!"}`); r.code != 403 {
				t.Fatalf("seed failure = %d %s", r.code, r.raw)
			}
			body := fmt.Sprintf(`{"password":"sekret-1","code":%q}`, e.codeAt(sec, e.clock.now))
			want := 500
			switch kind {
			case "corrupt_secret":
				var enc string
				if err := e.db.QueryRow(`SELECT totp_secret_enc FROM users`).Scan(&enc); err != nil {
					t.Fatal(err)
				}
				raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, "v1:"))
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)/2] ^= 1
				mustExec(t, e.s, `UPDATE users SET totp_secret_enc=?`, "v1:"+base64.StdEncoding.EncodeToString(raw))
				want = 503
			case "totp_write":
				mustExec(t, e.s, `CREATE TRIGGER fail_totp AFTER UPDATE OF totp_last_step ON users BEGIN SELECT RAISE(FAIL,'private storage failure'); END`)
			case "recovery_write":
				body = fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0])
				mustExec(t, e.s, `CREATE TRIGGER fail_recovery AFTER UPDATE ON user_recovery_codes BEGIN SELECT RAISE(FAIL,'private storage failure'); END`)
			}
			for i := 0; i < 6; i++ {
				r := c.post("reauth", body)
				if r.code != want || strings.Contains(r.raw, "private storage") {
					t.Errorf("internal failure %d = %d %s, want %d generic response", i, r.code, r.raw, want)
				}
			}
			if n := e.count(`SELECT failures FROM auth_throttle WHERE scope='mfa_user'`); n != 1 {
				t.Errorf("MFA failures = %d, want 1", n)
			}
			if n := e.count(`SELECT failures FROM auth_throttle WHERE scope='ip'`); n != 1 {
				t.Errorf("IP failures = %d, want 1", n)
			}
			if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
				t.Error("internal error consumed recovery code")
			}
			if e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, e.clock.now.Add(-11*time.Minute).Unix()/30) != 1 {
				t.Error("internal error advanced TOTP step")
			}
			if e.count(`SELECT count(*) FROM sessions WHERE sudo_until>?`, fmtTime(e.clock.now)) != 0 {
				t.Error("internal error granted sudo")
			}
		})
	}
}

// A challenge delete that removes no row is a storage anomaly, not an
// authentication verdict: everything (factor, attempts, budget) rolls back.
func TestFinishChallengeDeleteAnomalyRollsBack(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.1:1"))
	c := e.client("192.0.2.2:1")
	c.login(t)
	mustExec(t, e.s, `CREATE TRIGGER ignore_challenge_delete BEFORE DELETE ON mfa_challenges BEGIN SELECT RAISE(IGNORE); END`)
	r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0]))
	if r.code != 500 || r.errCode() != "internal" {
		t.Fatalf("delete anomaly = %d %s, want 500 internal", r.code, r.raw)
	}
	if r.cookie(SessionCookie) != nil || e.count(`SELECT count(*) FROM sessions WHERE mfa_passed=1 AND ip='192.0.2.2'`) != 0 {
		t.Fatal("delete anomaly minted a session")
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("delete anomaly consumed recovery code")
	}
	if e.count(`SELECT attempts FROM mfa_challenges`) != 0 {
		t.Fatal("delete anomaly burned a challenge attempt")
	}
	if e.count(`SELECT count(*) FROM auth_throttle WHERE scope='mfa_user'`) != 0 {
		t.Fatal("delete anomaly counted an MFA failure")
	}
	mustExec(t, e.s, `DROP TRIGGER ignore_challenge_delete`)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 200 {
		t.Fatalf("retry after anomaly = %d %s", r.code, r.raw)
	}
}

func TestReauthPreservesLastLogin(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(fmt.Sprintf("mfa=%v", mfa), func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.1:1")
			var sec string
			if mfa {
				sec, _ = e.enroll(c)
				c = e.client("192.0.2.1:2")
				e.clock.advance(time.Minute)
				c.login(t)
				if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 200 {
					t.Fatalf("mfa login = %d %s", r.code, r.raw)
				}
			} else {
				c.login(t)
			}
			loginAt := fmtTime(e.clock.now)
			e.clock.advance(20 * time.Minute)
			body := `{"password":"sekret-1"}`
			if mfa {
				body = fmt.Sprintf(`{"password":"sekret-1","code":%q}`, e.codeAt(sec, e.clock.now))
			}
			if r := c.post("reauth", body); r.code != 200 {
				t.Fatalf("reauth = %d %s", r.code, r.raw)
			}
			var got string
			if err := e.db.QueryRow(`SELECT last_login_at FROM users`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != loginAt {
				t.Fatalf("last_login_at = %s after reauth, want login time %s", got, loginAt)
			}
			if r := c.do("GET", "me", "", nil); r.code != 200 {
				t.Fatalf("me = %d", r.code)
			} else if u := r.body["user"].(map[string]any); u["last_login_at"] != loginAt {
				t.Fatalf("me last_login_at = %v, want %s", u["last_login_at"], loginAt)
			}
		})
	}
}

func TestAuthenticateStillRecordsLogin(t *testing.T) {
	e := newMFAEnv(t, false)
	e.clock.advance(time.Hour)
	u, err := e.s.Authenticate(context.Background(), "admin", "sekret-1", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if u.LastLoginAt == nil || !u.LastLoginAt.Equal(e.clock.now) {
		t.Fatalf("returned last_login_at = %v", u.LastLoginAt)
	}
	if e.count(`SELECT count(*) FROM users WHERE last_login_at=?`, fmtTime(e.clock.now)) != 1 {
		t.Fatal("Authenticate must persist last_login_at")
	}
}

func TestCreateInsertErrorPreservesCause(t *testing.T) {
	e := newMFAEnv(t, false)
	_, err := e.s.Create(context.Background(), "admin", "pw-secret-value", "admin")
	if err == nil {
		t.Fatal("duplicate accepted")
	}
	var coded interface{ Code() int }
	if !strings.HasPrefix(err.Error(), "auth: could not create user") || !errors.As(err, &coded) {
		t.Fatalf("duplicate error = %v (%T), want wrapped driver cause", err, err)
	}
	mustExec(t, e.s, `CREATE TRIGGER reject_user BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT,'storage offline'); END`)
	_, err = e.s.Create(context.Background(), "other", "pw-secret-value", "user")
	if err == nil || !errors.As(err, &coded) || !strings.Contains(err.Error(), "storage offline") {
		t.Fatalf("insert failure = %v, want wrapped cause", err)
	}
	if strings.Contains(err.Error(), "pw-secret-value") || strings.Contains(err.Error(), "argon2id") {
		t.Fatalf("error leaks credential material: %v", err)
	}
}
