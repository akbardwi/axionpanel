package auth

import (
	"context"
	"testing"
)

func TestAuditServiceMFAAuthenticateIsPasswordOnly(t *testing.T) {
	e := newMFAEnv(t, true)
	e.enroll(e.client("192.0.2.8:1"))
	_, err := e.s.Authenticate(context.Background(), "admin", "sekret-1", "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	requireEvent(t, e, "auth.password.verify", "success")
	if e.count(`SELECT count(*) FROM audit_log WHERE action='auth.login' AND outcome='success'`) != 1 {
		t.Fatal("MFA password verification mislabeled completed login")
	}
}
func TestAuditVerifiedActorNotLabeledCandidate(t *testing.T) {
	e := newMFAEnv(t, true)
	e.client("192.0.2.8:1").login(t)
	if e.count(`SELECT count(*) FROM audit_log WHERE user_id IS NOT NULL AND json_type(details,'$.candidate_verified') IS NOT NULL`) != 0 {
		t.Fatal("verified actor mislabeled as unverified candidate")
	}
}
