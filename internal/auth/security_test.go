package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOriginRequiredOnEveryAuthPost(t *testing.T) {
	s, _, _ := newTestService(t)
	mux := http.NewServeMux()
	s.Register(mux)
	for _, path := range []string{"login", "login/mfa", "logout", "reauth", "mfa/setup", "mfa/enable", "mfa/disable"} {
		for _, origin := range []string{"", "null", "https://attacker.test", "https://localhost:7800/"} {
			r := httptest.NewRequest("POST", "/api/v1/auth/"+path, strings.NewReader(`{}`))
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Errorf("%s origin %q: %d want 403", path, origin, w.Code)
			}
		}
	}
}

func TestSuspendedSessionRejected(t *testing.T) {
	s, _, _ := newTestService(t)
	u := mustCreate(t, s, "admin", "pw")
	sess, err := s.CreateSession(context.Background(), u.ID, "::1", "test")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE users SET status='suspended' WHERE id=?`, u.ID)
	if _, err := s.Lookup(context.Background(), hashToken(sess.Token)); err == nil {
		t.Fatal("suspended session accepted")
	}
}

func TestUnsafePHCRejected(t *testing.T) {
	salt := "MDEyMzQ1Njc4OWFiY2RlZg"
	key := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
	for _, params := range []string{"m=1,t=1,p=0", "m=4294967295,t=2,p=1", "m=19456,t=0,p=1", "m=19456,t=4294967295,p=1", "m=19456,t=2,p=256", "m=19456,t=2,p=1,p=1", "m=19456,t=2", "m=19456,t=2,p=1,x=1"} {
		t.Run(params, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("PHC panicked: %v", v)
				}
			}()
			if VerifyPassword("argon2id$v=19$"+params+"$"+salt+"$"+key, "pw") {
				t.Fatal("unsafe PHC accepted")
			}
		})
	}
	if VerifyPassword("argon2id$v=18$m=19456,t=2,p=1$"+salt+"$"+key, "pw") {
		t.Fatal("bad version")
	}
}
