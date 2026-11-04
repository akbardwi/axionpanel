package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type auditRow struct {
	User                         sql.NullInt64
	Username                     sql.NullString
	IP, Action, Details, Outcome string
}

func auditRows(t *testing.T, e *mfaEnv) []auditRow {
	t.Helper()
	rows, err := e.db.Query(`SELECT user_id,username,ip,action,details,outcome FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []auditRow{}
	for rows.Next() {
		var a auditRow
		if err = rows.Scan(&a.User, &a.Username, &a.IP, &a.Action, &a.Details, &a.Outcome); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
func rejectAudit(t *testing.T, e *mfaEnv, action string) {
	t.Helper()
	mustExec(t, e.s, `CREATE TRIGGER reject_audit BEFORE INSERT ON audit_log WHEN NEW.action=`+fmt.Sprintf("'%s'", action)+` BEGIN SELECT RAISE(ABORT,'audit private storage secret'); END`)
}
func requireEvent(t *testing.T, e *mfaEnv, action, outcome string) auditRow {
	t.Helper()
	var found []auditRow
	for _, a := range auditRows(t, e) {
		if a.Action == action && a.Outcome == outcome {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s %s events=%d; rows=%+v", action, outcome, len(found), auditRows(t, e))
	}
	return found[0]
}
func noAuditSecrets(t *testing.T, e *mfaEnv, secrets ...string) {
	t.Helper()
	for _, a := range auditRows(t, e) {
		row := fmt.Sprintf("%+v", a)
		for _, secret := range secrets {
			if secret != "" && strings.Contains(row, secret) {
				t.Fatalf("audit contains secret %q", secret)
			}
		}
	}
}

func TestAuditLoginSuccessAtomicSession(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.9:19")
	r := c.do("POST", "login", `{"username":"admin","password":"sekret-1"}`, map[string]string{"X-Forwarded-For": "198.51.100.1", "X-Actor-ID": "999", "User-Agent": "header-secret"})
	if r.code != 200 {
		t.Fatalf("login %d %s", r.code, r.raw)
	}
	a := requireEvent(t, e, "auth.login", "success")
	if !a.User.Valid || a.Username.String != "admin" || a.IP != "192.0.2.9" {
		t.Fatalf("actor spoofed: %+v", a)
	}
	noAuditSecrets(t, e, "sekret-1", "header-secret", c.csrf, c.cookies[SessionCookie].Value, hashToken(c.cookies[SessionCookie].Value), hashToken(c.csrf))
	// Polling must not emit events.
	before := len(auditRows(t, e))
	for i := 0; i < 3; i++ {
		if r := c.do("GET", "me", "", nil); r.code != 200 {
			t.Fatal(r)
		}
	}
	if len(auditRows(t, e)) != before {
		t.Fatal("me emitted per-poll audit")
	}
}
func TestAuditLoginFailureGenericBoundedAndLockout(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.LockoutThreshold = 1 })
	c := e.client("192.0.2.9:1")
	candidate := "ghost\nforged\t'\""
	body, _ := json.Marshal(map[string]string{"username": candidate, "password": "wrong-secret"})
	r := c.post("login", string(body))
	if r.code != 401 {
		t.Fatalf("unknown user %d %s", r.code, r.raw)
	}
	a := requireEvent(t, e, "auth.login", "failure")
	if a.User.Valid || a.Username.Valid {
		t.Fatalf("unverified actor %+v", a)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(a.Details), &d); err != nil {
		t.Fatal(err)
	}
	if d["candidate_verified"] != false || strings.ContainsAny(d["candidate_username"].(string), "\n\t\r") {
		t.Fatalf("unsafe candidate %s", a.Details)
	}
	r = c.post("login", string(body))
	if r.code != 423 {
		t.Fatalf("lockout %d %s", r.code, r.raw)
	}
	requireEvent(t, e, "auth.login", "denied")
	other := e.client("192.0.2.10:1")
	r = other.post("login", `{"username":"admin","password":"wrong-secret"}`)
	if r.code != 401 || strings.Contains(r.raw, "admin") {
		t.Fatalf("enumeration %d %s", r.code, r.raw)
	}
	noAuditSecrets(t, e, "wrong-secret")
}
func TestAuditLoginInsertFailureNoCredential(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.9:1")
	rejectAudit(t, e, "auth.login")
	r := c.post("login", `{"username":"admin","password":"sekret-1"}`)
	if r.code != 500 || r.cookie(SessionCookie) != nil || r.cookie(CSRFCookie) != nil || r.cookie(MFACookie) != nil || strings.Contains(r.raw, "audit private") {
		t.Fatalf("audit fail granted credential %d %s %+v", r.code, r.raw, r.cookies)
	}
	if e.count(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("session persisted without audit")
	}
}
func TestAuditRejectedLoginStorageFailureIsInternal(t *testing.T) {
	e := newMFAEnv(t, true)
	rejectAudit(t, e, "auth.login")
	r := e.client("192.0.2.9:1").post("login", `{"username":"ghost","password":"wrong"}`)
	if r.code != 500 || r.cookie(SessionCookie) != nil || strings.Contains(r.raw, "audit private") {
		t.Fatalf("failure not fail-closed %d %s", r.code, r.raw)
	}
}
