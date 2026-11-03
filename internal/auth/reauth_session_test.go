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

// Run mutation after real auth/CSRF middleware captures its session. This
// fixes the interleaving without sleeps or production synchronization hooks.
func reauthAfterLookup(t *testing.T, c *client, body string, mutate func(*Session)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/auth/reauth", strings.NewReader(body))
	r.RemoteAddr = c.addr
	r.Header.Set("X-CSRF-Token", c.csrf)
	r.AddCookie(c.cookies[SessionCookie])
	w := httptest.NewRecorder()
	c.env.s.requireAuth(c.env.s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutate(sessionFrom(r.Context()))
		c.env.s.handleReauth(w, r)
	}))).ServeHTTP(w, r)
	return w
}

func TestReauthSessionReadFailureIsInternal(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	_, codes := e.enroll(c)
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0]), func(sess *Session) {
		// A genuine storage failure (table gone) after password verification,
		// distinct from a missing row.
		mustExec(t, e.s, `DROP TABLE sessions`)
	})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("session read failure = %d %s, want 500", w.Code, w.Body)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
		t.Error("read failure consumed recovery code")
	}
}

func TestReauthRejectsRevokedSession(t *testing.T) {
	// Session is deleted after Lookup with no replacement: the revalidation
	// finds no row and must refuse sudo without consuming the factor.
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	_, codes := e.enroll(c)
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0]), func(sess *Session) {
		if err := e.s.DeleteSession(context.Background(), sess.TokenHash); err != nil {
			t.Fatal(err)
		}
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked session = %d %s, want 401", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`); n != 0 {
		t.Errorf("revoked session consumed recovery codes = %d, want 0", n)
	}
}

func TestReauthRejectsReusedSessionID(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	_, codes := e.enroll(c)
	other := mustCreate(t, e.s, "other", "different-password")
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0]), func(sess *Session) {
		if err := e.s.DeleteSession(context.Background(), sess.TokenHash); err != nil {
			t.Fatal(err)
		}
		replacement, err := e.s.CreateSession(context.Background(), other.ID, "192.0.2.2", "other-browser")
		if err != nil {
			t.Fatal(err)
		}
		if replacement.ID != sess.ID || replacement.TokenHash == sess.TokenHash {
			t.Fatalf("test requires SQLite row-ID reuse with a different token: old=%d new=%d", sess.ID, replacement.ID)
		}
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked original = %d %s, want 401", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`); n != 0 {
		t.Errorf("replacement sessions granted sudo = %d, want 0", n)
	}
	if n := e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`); n != 0 {
		t.Errorf("revoked original consumed recovery codes = %d, want 0", n)
	}
}

func TestReauthRejectsDeletedSessionWithFactorRollback(t *testing.T) {
	// Revalidation must reject the reused ID before consuming a valid TOTP.
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	sec, _ := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	code := e.codeAt(sec, e.clock.now)
	other := mustCreate(t, e.s, "other", "different-password")
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","code":%q}`, code), func(sess *Session) {
		if err := e.s.DeleteSession(context.Background(), sess.TokenHash); err != nil {
			t.Fatal(err)
		}
		replacement, err := e.s.CreateSession(context.Background(), other.ID, "192.0.2.2", "other-browser")
		if err != nil {
			t.Fatal(err)
		}
		if replacement.ID != sess.ID {
			t.Fatalf("test requires row-ID reuse: old=%d new=%d", sess.ID, replacement.ID)
		}
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("deleted session = %d %s, want 401", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`); n != 0 {
		t.Errorf("sudo granted = %d, want 0", n)
	}
	// The only stored TOTP step must be the enrollment step; the consumed
	// reauth step must have rolled back.
	if n := e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, e.clock.now.Add(-11*time.Minute).Unix()/30); n != 1 {
		t.Errorf("rolled-back reauth advanced the TOTP step: step %d rows = %d, want 1", e.clock.now.Add(-11*time.Minute).Unix()/30, n)
	}
}

func TestReauthFactorRollbackOnZeroRowUpdate(t *testing.T) {
	// The correct TOTP code is consumed (totp_last_step advances), then the
	// identity UPDATE affects zero rows and forces a rollback that must
	// restore the consumed step. A trigger makes the UPDATE a no-op without
	// raising an error, exercising the n != 1 branch.
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	sec, _ := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
	code := e.codeAt(sec, e.clock.now)
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","code":%q}`, code), func(sess *Session) {
		mustExec(t, e.s, `CREATE TRIGGER ignore_sudo BEFORE UPDATE OF sudo_until ON sessions BEGIN SELECT RAISE(IGNORE); END`)
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("zero-row update = %d %s, want 401", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`); n != 0 {
		t.Errorf("sudo granted = %d, want 0", n)
	}
	// The consumed step must have rolled back to the enrollment step.
	if n := e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, e.clock.now.Add(-11*time.Minute).Unix()/30); n != 1 {
		t.Errorf("consumed TOTP step not rolled back: enrollment step rows = %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, e.clock.now.Unix()/30); n != 0 {
		t.Errorf("consumed TOTP step persisted = %d, want 0", n)
	}
}

func TestReauthRejectsConcurrentMFAEnable(t *testing.T) {
	// The session proved only the password while MFA was off. Between Lookup
	// and the reauth write lock the account flips to MFA-enabled: the freshly
	// loaded totp_enabled must force rejection, since this session never
	// satisfied the second factor.
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	c.login(t)
	// Flip MFA on after Lookup (where mfa_passed was still irrelevant because
	// totp_enabled was 0) but before handleReauth revalidates.
	w := reauthAfterLookup(t, c, `{"password":"sekret-1"}`, func(sess *Session) {
		mustExec(t, e.s, `UPDATE users SET totp_enabled=1, totp_secret_enc='v1:invalid' WHERE id=?`, sess.UserID)
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("reauth after concurrent enable = %d %s, want 401", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`); n != 0 {
		t.Errorf("sudo granted without factor = %d, want 0", n)
	}
}

// Authentication's success write happens after its user snapshot and Argon2,
// before handleReauth takes its own write lock. Triggers fix that interleaving.
func TestReauthReloadsMFAAfterPasswordVerification(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enable=%v", enabled), func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.1:1")
			if enabled {
				c.login(t)
				mustExec(t, e.s, `CREATE TRIGGER change_mfa AFTER UPDATE OF failed_logins ON users WHEN NEW.failed_logins=0 BEGIN
					UPDATE users SET totp_enabled=1,totp_secret_enc='unopenable' WHERE id=NEW.id;
					UPDATE sessions SET mfa_passed=1 WHERE user_id=NEW.id;
				END`)
			} else {
				e.enroll(c)
				mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
				mustExec(t, e.s, `CREATE TRIGGER change_mfa AFTER UPDATE OF failed_logins ON users WHEN NEW.failed_logins=0 BEGIN
					UPDATE users SET totp_enabled=0,totp_secret_enc=NULL WHERE id=NEW.id;
				END`)
			}
			w := reauthAfterLookup(t, c, `{"password":"sekret-1"}`, func(*Session) {})
			want := http.StatusOK
			if enabled {
				want = http.StatusForbidden
			}
			if w.Code != want {
				t.Fatalf("current MFA state = %d %s, want %d", w.Code, w.Body, want)
			}
		})
	}
}

func TestReauthRevalidatesCurrentSessionState(t *testing.T) {
	for _, change := range []string{"token", "user", "inactive", "mfa_unsatisfied", "absolute", "idle", "authenticated_user"} {
		t.Run(change, func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.1:1")
			_, codes := e.enroll(c)
			other := mustCreate(t, e.s, "other", "sekret-1")
			mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
			w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0]), func(sess *Session) {
				switch change {
				case "token":
					mustExec(t, e.s, `UPDATE sessions SET token_hash=? WHERE id=?`, hashToken("replacement"), sess.ID)
				case "user":
					mustExec(t, e.s, `UPDATE sessions SET user_id=? WHERE id=?`, other.ID, sess.ID)
				case "inactive":
					mustExec(t, e.s, `CREATE TRIGGER suspend_user AFTER UPDATE OF failed_logins ON users WHEN NEW.failed_logins=0 BEGIN UPDATE users SET status='suspended' WHERE id=NEW.id; END`)
				case "mfa_unsatisfied":
					mustExec(t, e.s, `UPDATE sessions SET mfa_passed=0 WHERE id=?`, sess.ID)
				case "absolute":
					mustExec(t, e.s, `UPDATE sessions SET expires_at=? WHERE id=?`, fmtTime(e.clock.now), sess.ID)
				case "idle":
					mustExec(t, e.s, `UPDATE sessions SET last_seen_at=? WHERE id=?`, fmtTime(e.clock.now.Add(-e.s.cfg.SessionIdleTTL)), sess.ID)
				case "authenticated_user":
					// Username was reassigned after middleware captured the user.
					mustExec(t, e.s, `UPDATE users SET username='renamed' WHERE id=?`, sess.UserID)
					mustExec(t, e.s, `UPDATE users SET username='admin' WHERE id=?`, other.ID)
				}
			})
			if w.Code != http.StatusUnauthorized {
				t.Errorf("changed session = %d %s, want 401", w.Code, w.Body)
			}
			if e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM auth_throttle WHERE scope='mfa_user'`) != 0 {
				t.Error("changed session granted sudo, consumed factor or burned MFA budget")
			}
		})
	}
}

func TestReauthRequiresExactlyOneCurrentFactor(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprintf("both=%v", both), func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.1:1")
			sec, codes := e.enroll(c)
			e.clock.advance(time.Minute)
			mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
			body := `{"password":"sekret-1"}`
			if both {
				body = fmt.Sprintf(`{"password":"sekret-1","code":%q,"recovery_code":%q}`, e.codeAt(sec, e.clock.now), codes[0])
			}
			r := c.post("reauth", body)
			if r.code != http.StatusForbidden {
				t.Errorf("factor cardinality = %d %s, want 403", r.code, r.raw)
			}
			if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 || e.count(`SELECT count(*) FROM auth_throttle WHERE scope='mfa_user'`) != 0 {
				t.Error("invalid factor cardinality consumed factor or failure budget")
			}
		})
	}
}

func TestReauthUsesCurrentDisabledMFAWithoutFactor(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	e.enroll(c)
	mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
	w := reauthAfterLookup(t, c, `{"password":"sekret-1"}`, func(sess *Session) {
		mustExec(t, e.s, `UPDATE users SET totp_enabled=0,totp_secret_enc=NULL,totp_last_step=NULL WHERE id=?`, sess.UserID)
	})
	if w.Code != http.StatusOK {
		t.Errorf("reauth with currently disabled MFA = %d %s, want 200", w.Code, w.Body)
	}
}

func TestReauthRejectsConcurrentMFADisable(t *testing.T) {
	// The session is MFA-enabled; the client includes a correct code. Between
	// Lookup and the reauth write lock, MFA is disabled. The freshly loaded
	// totp_enabled must reflect the new state: the stale snapshot would have
	// consumed the factor, but the fresh state rejects the surplus code (400).
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.1:1")
	sec, _ := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	mustExec(t, e.s, `UPDATE sessions SET sudo_until=NULL`)
	code := e.codeAt(sec, e.clock.now)
	w := reauthAfterLookup(t, c, fmt.Sprintf(`{"password":"sekret-1","code":%q}`, code), func(sess *Session) {
		mustExec(t, e.s, `UPDATE users SET totp_enabled=0 WHERE id=?`, sess.UserID)
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("reauth after concurrent disable = %d %s, want 400", w.Code, w.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE sudo_until IS NOT NULL`); n != 0 {
		t.Errorf("sudo granted = %d, want 0", n)
	}
	if n := e.count(`SELECT count(*) FROM users WHERE totp_last_step=?`, e.clock.now.Unix()/30); n != 0 {
		t.Errorf("TOTP step consumed = %d, want 0 (factor not required)", n)
	}
}
