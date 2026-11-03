package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequireAuthAndSessionFrom covers the exported seam the panel uses to
// mount authenticated, non-CSRF GET routes and read the signed-in user's ID
// for agent audit attribution.
func TestRequireAuthAndSessionFrom(t *testing.T) {
	s, _, _ := newTestService(t)
	u := mustCreate(t, s, "alice", "correct horse battery staple")
	sess, err := s.CreateSession(context.Background(), u.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	var gotID int64
	var reached bool
	h := s.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		s := SessionFrom(r.Context())
		if s == nil {
			t.Error("SessionFrom returned nil on an authenticated request")
			return
		}
		gotID = s.UserID
		w.WriteHeader(http.StatusNoContent)
	}))

	// Unauthenticated: 401, handler untouched.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized || reached {
		t.Fatalf("unauthenticated = %d reached=%v, want 401/not reached", rec.Code, reached)
	}

	// Authenticated via session cookie.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.Token})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("authenticated = %d reached=%v", rec.Code, reached)
	}
	if gotID != u.ID {
		t.Fatalf("SessionFrom user id = %d, want %d", gotID, u.ID)
	}
}
