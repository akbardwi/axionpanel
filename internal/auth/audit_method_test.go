package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestAuditReauthRecordsUsedFactor(t *testing.T) {
	for _, kind := range []string{"totp_success", "recovery_locked"} {
		t.Run(kind, func(t *testing.T) {
			e := newMFAEnv(t, true)
			c := e.client("192.0.2.8:1")
			sec, codes := e.enroll(c)
			e.clock.advance(time.Minute)
			body := fmt.Sprintf(`{"password":"sekret-1","code":%q}`, e.codeAt(sec, e.clock.now))
			method, outcome, want := "totp", "success", 200
			if kind == "recovery_locked" {
				body = fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[0])
				method, outcome, want = "recovery_code", "denied", 423
				mustExec(t, e.s, `INSERT INTO auth_throttle(scope,key,failures,window_start) VALUES('mfa_user',?,5,?)`, mfaKey(1), fmtTime(e.clock.now))
			}
			before := e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth' AND outcome=? AND json_extract(details,'$.method')=?`, outcome, method)
			r := c.post("reauth", body)
			if r.code != want {
				t.Fatalf("reauth %d %s", r.code, r.raw)
			}
			if n := e.count(`SELECT count(*) FROM audit_log WHERE action='auth.reauth' AND outcome=? AND json_extract(details,'$.method')=?`, outcome, method); n != before+1 {
				t.Fatalf("used factor %q not recorded", method)
			}
		})
	}
}
