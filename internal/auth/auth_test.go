package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/store"
)

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time          { return f.now }
func (f *fakeClock) advance(d time.Duration) { f.now = f.now.Add(d) }

func newTestService(t *testing.T) (*Service, *fakeClock, *sql.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)}
	cfg := DefaultConfig()
	return New(db, cfg, clock), clock, db
}

func mustCreate(t *testing.T, s *Service, username, password string) *User {
	t.Helper()
	u, err := s.Create(context.Background(), username, password, "admin")
	if err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	return u
}

func sessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestPasswordHashRoundTripAndFormat(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "argon2id$") {
		t.Errorf("hash must use the argon2id encoded format, got %.30q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("correct password must verify")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("wrong password must not verify")
	}
	if VerifyPassword("not-a-hash", "correct horse battery staple") {
		t.Error("garbage hash must not verify")
	}
}

func TestCreateAndAuthenticate(t *testing.T) {
	s, _, _ := newTestService(t)
	ctx := context.Background()
	mustCreate(t, s, "admin", "sekret-1")

	if _, err := s.Create(ctx, "admin", "other", "admin"); err == nil {
		t.Error("duplicate username must fail")
	}
	if _, err := s.Create(ctx, "", "pw", "admin"); err == nil {
		t.Error("empty username must fail")
	}
	if _, err := s.Create(ctx, "u2", "x", "root"); err == nil {
		t.Error("invalid role must fail")
	}

	u, err := s.Authenticate(ctx, "ADMIN", "sekret-1", "192.0.2.10")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.Username != "admin" {
		t.Errorf("username = %q, want admin", u.Username)
	}
	if u.FailedLogins != 0 {
		t.Errorf("failed_logins = %d after success, want 0", u.FailedLogins)
	}

	if _, err := s.Authenticate(ctx, "admin", "sekret-2", "192.0.2.10"); err == nil {
		t.Error("wrong password must fail")
	}
}

func TestLoginLockout(t *testing.T) {
	s, clock, db := newTestService(t)
	ctx := context.Background()
	mustCreate(t, s, "admin", "sekret-1")

	for i := 0; i < 5; i++ {
		if _, err := s.Authenticate(ctx, "admin", "wrong", "192.0.2.10"); err == nil {
			t.Fatalf("attempt %d must fail", i)
		}
	}
	if _, err := s.Authenticate(ctx, "admin", "sekret-1", "192.0.2.10"); err != ErrLockedOut {
		t.Errorf("sixth attempt err = %v, want ErrLockedOut", err)
	}

	clock.advance(16 * time.Minute)
	if _, err := s.Authenticate(ctx, "admin", "sekret-1", "192.0.2.10"); err != nil {
		t.Errorf("lockout must expire after 15 minutes, got %v", err)
	}
	var failed int
	if err := db.QueryRow(`SELECT failed_logins FROM users WHERE username = 'admin'`).Scan(&failed); err != nil {
		t.Fatalf("query: %v", err)
	}
	if failed != 0 {
		t.Errorf("failed_logins = %d after lockout expiry success, want 0", failed)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s, _, db := newTestService(t)
	ctx := context.Background()
	u := mustCreate(t, s, "admin", "sekret-1")

	sess, err := s.CreateSession(ctx, u.ID, "192.0.2.10", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if len(sess.Token) < 40 || len(sess.CSRFToken) < 40 {
		t.Error("session and csrf tokens must be long random values")
	}
	if !strings.HasPrefix(sess.Token, "axp_") {
		t.Errorf("session token = %.12q, want axp_ prefix", sess.Token)
	}

	got, err := s.Lookup(ctx, sessionHash(sess.Token))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.UserID != u.ID || got.User.Username != "admin" {
		t.Errorf("lookup returned user %d (%s), want %d (admin)", got.UserID, got.User.Username, u.ID)
	}

	// Spec §5.1: the database stores only the SHA-256 hash, never the raw token.
	var stored, storedCSRF string
	if err := db.QueryRow(`SELECT token_hash, csrf_token_hash FROM sessions`).Scan(&stored, &storedCSRF); err != nil {
		t.Fatalf("query session row: %v", err)
	}
	if stored != sessionHash(sess.Token) || stored == sess.Token {
		t.Error("sessions.token_hash must be the SHA-256 of the token, not the token")
	}
	if storedCSRF != sessionHash(sess.CSRFToken) {
		t.Error("sessions.csrf_token_hash must be the SHA-256 of the csrf token")
	}

	if err := s.DeleteSession(ctx, sessionHash(sess.Token)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Lookup(ctx, sessionHash(sess.Token)); err == nil {
		t.Error("deleted session must not resolve")
	}
}

func TestSessionExpiry(t *testing.T) {
	t.Run("idle timeout expires the session", func(t *testing.T) {
		s, clock, db := newTestService(t)
		ctx := context.Background()
		u := mustCreate(t, s, "admin", "sekret-1")
		sess, _ := s.CreateSession(ctx, u.ID, "192.0.2.10", "ua")

		clock.advance(3 * time.Hour) // past idle timeout, before absolute
		if _, err := s.Lookup(ctx, sessionHash(sess.Token)); err == nil {
			t.Fatal("session must expire after idle timeout")
		}
		var n int
		db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n)
		if n != 0 {
			t.Errorf("expired session rows = %d, want 0", n)
		}
	})

	t.Run("activity keeps the session alive within the absolute window", func(t *testing.T) {
		s, clock, _ := newTestService(t)
		ctx := context.Background()
		u := mustCreate(t, s, "admin", "sekret-1")
		sess, _ := s.CreateSession(ctx, u.ID, "192.0.2.10", "ua")

		for i := 0; i < 18; i++ { // 18 hours of hourly use, inside the 2h idle window
			clock.advance(1 * time.Hour)
			if _, err := s.Lookup(ctx, sessionHash(sess.Token)); err != nil {
				t.Fatalf("lookup %d: %v", i, err)
			}
		}
	})

	t.Run("absolute timeout expires the session despite activity", func(t *testing.T) {
		s, clock, _ := newTestService(t)
		ctx := context.Background()
		u := mustCreate(t, s, "admin", "sekret-1")
		sess, _ := s.CreateSession(ctx, u.ID, "192.0.2.10", "ua")

		for i := 0; i < 27; i++ { // hourly use for 27 hours; idle never trips
			clock.advance(1 * time.Hour)
			_, err := s.Lookup(ctx, sessionHash(sess.Token))
			if i < 23 {
				if err != nil {
					t.Fatalf("lookup %d: %v", i, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("lookup %d: session must hit the absolute 24h limit", i)
			}
		}
	})
}

func newTestServer(t *testing.T) (*http.ServeMux, *Service, *fakeClock, string) {
	t.Helper()
	s, clock, db := newTestService(t)
	mux := http.NewServeMux()
	s.Register(mux)
	_, err := db.Exec(`INSERT INTO users (username, password_hash, role, status) VALUES ('admin', 'x', 'admin', 'active')`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return mux, s, clock, ""
}

func TestLoginHandler(t *testing.T) {
	t.Run("logs in and returns csrf token", func(t *testing.T) {
		mux, s, _, _ := newTestServer(t)
		hash, _ := HashPassword("sekret-1")
		mustExec(t, s, `UPDATE users SET password_hash = ? WHERE username = 'admin'`, hash)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"sekret-1"}`))
		req.Header.Set("Origin", testOrigin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		cookies := rec.Result().Cookies()
		var cookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "axp_session" {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("axp_session cookie must be set")
		}
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie flags = %+v, want HttpOnly + Secure + SameSite=Strict", cookie)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"csrf_token"`) || !strings.Contains(body, `"mfa_required":false`) {
			t.Errorf("body = %s, want csrf_token and mfa_required", body)
		}
	})

	t.Run("wrong password is a 401 with generic error", func(t *testing.T) {
		mux, s, _, _ := newTestServer(t)
		hash, _ := HashPassword("sekret-1")
		mustExec(t, s, `UPDATE users SET password_hash = ? WHERE username = 'admin'`, hash)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"nope"}`))
		req.Header.Set("Origin", testOrigin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "nope") {
			t.Error("response must not echo the submitted password")
		}
	})

	t.Run("missing username is a 400", func(t *testing.T) {
		mux, _, _, _ := newTestServer(t)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"x"}`))
		req.Header.Set("Origin", testOrigin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func mustExec(t *testing.T, s *Service, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatalf("exec %s: %v", query, err)
	}
}

func TestAuthAndCSRFMiddleware(t *testing.T) {
	mux, s, _, _ := newTestServer(t)
	hash, _ := HashPassword("sekret-1")
	mustExec(t, s, `UPDATE users SET password_hash = ? WHERE username = 'admin'`, hash)
	ctx := context.Background()
	u, err := s.Authenticate(ctx, "admin", "sekret-1", "192.0.2.10")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	sess, _ := s.CreateSession(ctx, u.ID, "192.0.2.10", "ua")
	cookie := &http.Cookie{Name: "axp_session", Value: sess.Token, Path: "/"}

	do := func(method, path, csrf string, withCookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		if withCookie {
			req.AddCookie(cookie)
		}
		if method == "POST" {
			req.Header.Set("Origin", testOrigin)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := do("GET", "/api/v1/auth/me", "", true); rec.Code != http.StatusOK {
		t.Errorf("GET /auth/me = %d, want 200", rec.Code)
	}
	if rec := do("GET", "/api/v1/auth/me", "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /auth/me without session = %d, want 401", rec.Code)
	}
	if rec := do("POST", "/api/v1/auth/logout", "", true); rec.Code != http.StatusForbidden {
		t.Errorf("POST without csrf = %d, want 403", rec.Code)
	}
	if rec := do("POST", "/api/v1/auth/logout", "wrong-token", true); rec.Code != http.StatusForbidden {
		t.Errorf("POST with wrong csrf = %d, want 403", rec.Code)
	}
	if rec := do("POST", "/api/v1/auth/logout", sess.CSRFToken, true); rec.Code != http.StatusOK {
		t.Errorf("POST with csrf = %d, want 200", rec.Code)
	}
	if _, err := s.Lookup(ctx, sessionHash(sess.Token)); err == nil {
		t.Error("logout must delete the session")
	}
}
