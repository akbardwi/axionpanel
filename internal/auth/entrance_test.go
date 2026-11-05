package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/store"
)

const testEntrancePath = "/AbcDEF019_-x"

func TestValidateEntrancePath(t *testing.T) {
	for _, path := range []string{"", testEntrancePath, "/abcdefghijkl", "/0123456789_-"} {
		if err := ValidateEntrancePath(path); err != nil {
			t.Errorf("valid path rejected: %v", err)
		}
	}
	for _, path := range []string{"/", "abcdefghijkl", "/abcdefghijk", "/abcdefghijklm", "/abcdefghijk+", "/abcdefghijk=", "/abcdefghijk/", "/abcdefghijk?", "/abcdefghijk#", "/abcdefghijk%", "/abcdefghijk ", "/abcdefghijé", " /abcdefghijkl", "/abcdefghijkl\n"} {
		if err := ValidateEntrancePath(path); err == nil {
			t.Error("invalid path accepted")
		}
	}
}

func TestEntranceDisabledReturnsOriginal(t *testing.T) {
	s, _, _ := newTestService(t)
	next := http.NewServeMux()
	got, err := s.Entrance("", next)
	if err != nil || got != next {
		t.Fatalf("disabled gate changed handler: %v", err)
	}
	if got, err := s.Entrance("", nil); got != nil || err != nil {
		t.Fatalf("disabled gate must preserve even nil handler: %v", err)
	}
	if got, err := s.Entrance(testEntrancePath, nil); got != nil || err == nil {
		t.Fatalf("enabled gate without a handler must fail initialization: %v", err)
	}
	forwarded := false
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusAccepted)
	})
	h := mustEntrance(t, s, "", forward)
	if rec := entranceDo(h, http.MethodPost, "/anything"); rec.Code != http.StatusAccepted || !forwarded {
		t.Fatalf("disabled gate did not forward traffic unchanged: status = %d", rec.Code)
	}
}

func TestEntranceRejectsInvalidConfig(t *testing.T) {
	s, _, _ := newTestService(t)
	for _, path := range []string{"/short", "/abcdefghijkl+", "abcdefghijkl", "/abcdefghijkl/"} {
		if h, err := s.Entrance(path, http.NotFoundHandler()); err == nil || h != nil {
			t.Errorf("Entrance(%q) = (%v, %v), want nil handler and error", path, h, err)
		}
	}
}

func mustEntrance(t *testing.T, s *Service, path string, next http.Handler) http.Handler {
	t.Helper()
	h, err := s.Entrance(path, next)
	if err != nil {
		t.Fatalf("entrance: %v", err)
	}
	return h
}

func entranceDo(h http.Handler, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestEntranceExactGetSetsCookieAndRedirects(t *testing.T) {
	s, clock, _ := newTestService(t)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("entrance path must not reach next") })
	h := mustEntrance(t, s, testEntrancePath, next)

	rec := entranceDo(h, http.MethodGet, testEntrancePath)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "AbcDEF019") {
		t.Error("Location must not leak the secret path")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if strings.Contains(rec.Body.String(), "AbcDEF019") {
		t.Error("body must not leak the secret path")
	}

	c := responseCookie(t, rec, "axp_entrance")
	if c == nil {
		t.Fatal("entrance cookie not set")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie flags = httpOnly:%v secure:%v sameSite:%v path:%q", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
	if c.MaxAge != 86400 {
		t.Errorf("MaxAge = %d, want 86400", c.MaxAge)
	}
	if want := clock.now.Add(24 * time.Hour); !c.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", c.Expires, want)
	}
	if c.Value == "" || c.Value == testEntrancePath || c.Value == strings.TrimPrefix(testEntrancePath, "/") {
		t.Errorf("cookie value must be a derivative, not the raw path")
	}
	if strings.Contains(c.Value, "AbcDEF019") {
		t.Errorf("cookie value leaks the secret path")
	}
	if got := responseCookie(t, rec, SessionCookie); got != nil {
		t.Error("entrance must not issue a session cookie")
	}
	if got := responseCookie(t, rec, CSRFCookie); got != nil {
		t.Error("entrance must not issue a CSRF cookie")
	}
	if got := responseCookie(t, rec, MFACookie); got != nil {
		t.Error("entrance must not issue an MFA cookie")
	}
}

func TestEntranceDeniesUnknownWithoutCookie(t *testing.T) {
	s, _, _ := newTestService(t)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated request reached next") })
	h := mustEntrance(t, s, testEntrancePath, next)

	for _, target := range []string{"/", "/login", "/dashboard", "/assets/app.js", "/api/v1/health", "/api/v1/auth/me", "/does-not-exist"} {
		rec := entranceDo(h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", target, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", target, got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s Referrer-Policy = %q, want no-referrer", target, got)
		}
		if responseCookie(t, rec, "axp_entrance") != nil {
			t.Errorf("%s must not set an entrance cookie", target)
		}
		if strings.Contains(rec.Body.String(), "AbcDEF019") {
			t.Errorf("%s body leaks the secret path", target)
		}
	}
}

func TestEntranceNonGetAndAliasesDenied(t *testing.T) {
	s, _, _ := newTestService(t)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("denied request reached next") })
	h := mustEntrance(t, s, testEntrancePath, next)

	cases := []struct{ method, target string }{
		{http.MethodHead, testEntrancePath},
		{http.MethodPost, testEntrancePath},
		{http.MethodPut, testEntrancePath},
		{http.MethodDelete, testEntrancePath},
		{http.MethodGet, testEntrancePath + "?x=1"},
		{http.MethodGet, testEntrancePath + "?"},
		{http.MethodGet, "/%41bcDEF019_-x"},
		{http.MethodGet, testEntrancePath + "/"},
	}
	for _, tc := range cases {
		rec := entranceDo(h, tc.method, tc.target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404", tc.method, tc.target, rec.Code)
		}
		if responseCookie(t, rec, "axp_entrance") != nil {
			t.Errorf("%s %s must not mint an entrance cookie", tc.method, tc.target)
		}
	}
}

func TestEntranceCookieAdmitsRefreshesAndFailsClosed(t *testing.T) {
	s, clock, _ := newTestService(t)
	reached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(http.StatusNoContent) })
	h := mustEntrance(t, s, testEntrancePath, next)

	first := entranceDo(h, http.MethodGet, testEntrancePath)
	cookie := responseCookie(t, first, "axp_entrance")
	if cookie == nil {
		t.Fatal("entrance cookie not set")
	}

	rec := entranceDo(h, http.MethodGet, "/dashboard", cookie)
	if rec.Code != http.StatusNoContent || reached != 1 {
		t.Fatalf("cookie replay status = %d reached = %d, want 204 and 1", rec.Code, reached)
	}

	// Secret-path aliases and non-GET methods remain denied even after discovery.
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, testEntrancePath + "?x=1"},
		{http.MethodGet, testEntrancePath + "?"},
		{http.MethodGet, "/%41bcDEF019_-x"},
		{http.MethodHead, testEntrancePath},
		{http.MethodPost, testEntrancePath},
	} {
		rec := entranceDo(h, tc.method, tc.target, cookie)
		if rec.Code != http.StatusNotFound || responseCookie(t, rec, EntranceCookie) != nil {
			t.Errorf("discovered secret alias/method status = %d, want 404 without cookie", rec.Code)
		}
	}

	// A refreshed visit keeps working and pushes expiry forward.
	clock.advance(2 * time.Hour)
	refresh := entranceDo(h, http.MethodGet, testEntrancePath, cookie)
	fresh := responseCookie(t, refresh, "axp_entrance")
	if refresh.Code != http.StatusSeeOther || fresh == nil || fresh.Value == cookie.Value {
		t.Fatalf("refresh status = %d, new cookie = %v", refresh.Code, fresh)
	}
	if !fresh.Expires.Equal(clock.now.Add(24 * time.Hour)) {
		t.Errorf("refreshed expiry = %v, want %v", fresh.Expires, clock.now.Add(24*time.Hour))
	}
	if rec := entranceDo(h, http.MethodGet, "/dashboard", fresh); rec.Code != http.StatusNoContent {
		t.Errorf("refreshed cookie status = %d, want 204", rec.Code)
	}

	// Tampering inside the encoded body must fail closed.
	body := []byte(cookie.Value)
	body[len(body)/2] = 'A'
	if string(body) == cookie.Value {
		body[len(body)/2] = 'B'
	}
	if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: "axp_entrance", Value: string(body)}); rec.Code != http.StatusNotFound {
		t.Errorf("tampered cookie status = %d, want 404", rec.Code)
	}
	if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: "axp_entrance", Value: strings.TrimPrefix(testEntrancePath, "/")}); rec.Code != http.StatusNotFound {
		t.Errorf("raw path as cookie status = %d, want 404", rec.Code)
	}

	// A cookie minted for another secret path must not open this gate.
	other, _, _ := newTestService(t)
	otherGate := mustEntrance(t, other, "/ZYXwvu987_-q", next)
	foreign := responseCookie(t, entranceDo(otherGate, http.MethodGet, "/ZYXwvu987_-q"), "axp_entrance")
	if foreign == nil {
		t.Fatal("foreign cookie not issued")
	}
	if rec := entranceDo(h, http.MethodGet, "/dashboard", foreign); rec.Code != http.StatusNotFound {
		t.Errorf("foreign cookie status = %d, want 404", rec.Code)
	}

	// Duplicate cookies fail closed rather than letting parsing pick a winner.
	dup := entranceDo(h, http.MethodGet, "/dashboard", fresh, fresh)
	if dup.Code != http.StatusNotFound {
		t.Errorf("duplicate cookies status = %d, want 404", dup.Code)
	}

	// Invalid duplicate values must not disappear during cookie parsing.
	request := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.Header.Set("Cookie", "axp_entrance="+fresh.Value+"; axp_entrance=\"unterminated")
	duplicate := httptest.NewRecorder()
	h.ServeHTTP(duplicate, request)
	if duplicate.Code != http.StatusNotFound {
		t.Errorf("malformed duplicate status = %d, want 404", duplicate.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.Header.Set("Cookie", "axp_entrance="+fresh.Value+"; axp_entrance =\"unterminated")
	duplicate = httptest.NewRecorder()
	h.ServeHTTP(duplicate, request)
	if duplicate.Code != http.StatusNotFound {
		t.Errorf("whitespace duplicate status = %d, want 404", duplicate.Code)
	}

	// Expiry boundary for the refreshed cookie: valid one second before 24h,
	// expired exactly at 24h from its own issue time.
	clock.advance(24*time.Hour - 1*time.Second)
	if rec := entranceDo(h, http.MethodGet, "/dashboard", fresh); rec.Code != http.StatusNoContent {
		t.Errorf("status at 24h-1s = %d, want 204", rec.Code)
	}
	clock.advance(1 * time.Second)
	if rec := entranceDo(h, http.MethodGet, "/dashboard", fresh); rec.Code != http.StatusNotFound {
		t.Errorf("status at exactly 24h = %d, want 404", rec.Code)
	}
}

func TestEntranceSessionBypassRequiresGenuineSession(t *testing.T) {
	s, clock, _ := newTestService(t)
	ctx := context.Background()
	u := mustCreate(t, s, "admin", "sekret-1")
	sess, err := s.CreateSession(ctx, u.ID, "198.51.100.7", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionFrom(r.Context()) != nil {
			t.Error("entrance gate must not attach a session to the request context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h := mustEntrance(t, s, testEntrancePath, next)

	if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: SessionCookie, Value: sess.Token}); rec.Code != http.StatusNoContent {
		t.Errorf("genuine session status = %d, want 204", rec.Code)
	}
	for _, token := range []string{"axp_forged", "axp_" + strings.Repeat("A", 43), "", strings.Repeat("z", 200)} {
		if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: SessionCookie, Value: token}); rec.Code != http.StatusNotFound {
			t.Errorf("forged session %q status = %d, want 404", token, rec.Code)
		}
	}
	if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: SessionCookie, Value: sess.Token}, &http.Cookie{Name: SessionCookie, Value: "axp_forged"}); rec.Code != http.StatusNotFound {
		t.Errorf("duplicate session cookies status = %d, want 404", rec.Code)
	}

	clock.advance(24*time.Hour + time.Minute)
	if rec := entranceDo(h, http.MethodGet, "/dashboard", &http.Cookie{Name: SessionCookie, Value: sess.Token}); rec.Code != http.StatusNotFound {
		t.Errorf("expired session status = %d, want 404", rec.Code)
	}

	// Entrance is discovery only: downstream auth still challenges and still
	// enforces CSRF/Origin, and no entrance cookie substitutes for a session.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	s.Register(mux)
	gated := mustEntrance(t, s, testEntrancePath, mux)

	entrance := responseCookie(t, entranceDo(gated, http.MethodGet, testEntrancePath), "axp_entrance")
	if entrance == nil {
		t.Fatal("entrance cookie not issued")
	}
	if rec := entranceDo(gated, http.MethodGet, "/dashboard", entrance); rec.Code != http.StatusOK {
		t.Errorf("UI route with entrance cookie status = %d, want 200", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodGet, "/api/v1/health", entrance); rec.Code != http.StatusOK {
		t.Errorf("health with entrance cookie status = %d, want 200", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodGet, "/api/v1/auth/me", entrance); rec.Code != http.StatusUnauthorized {
		t.Errorf("me with entrance cookie only status = %d, want 401", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodPost, "/api/v1/auth/logout", entrance); rec.Code != http.StatusForbidden {
		t.Errorf("logout with entrance cookie only status = %d, want 403", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodGet, "/api/v1/auth/me"); rec.Code != http.StatusNotFound {
		t.Errorf("me without any cookie status = %d, want 404", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodGet, "/api/v1/auth/me", &http.Cookie{Name: EntranceCookie, Value: "raw-path"}); rec.Code != http.StatusNotFound {
		t.Errorf("me with bogus entrance cookie status = %d, want 404", rec.Code)
	}
	if rec := entranceDo(gated, http.MethodGet, "/api/v1/auth/me", &http.Cookie{Name: SessionCookie, Value: sess.Token}); rec.Code != http.StatusNotFound {
		t.Errorf("me with expired session status = %d, want 404", rec.Code)
	}
}

func TestEntranceCookieSecureFlagFollowsCookiePolicy(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	clock := &fakeClock{now: time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)}
	safe := DefaultConfig()
	insecure := DefaultConfig()
	insecure.Origin = "http://127.0.0.1:7800"
	insecure.AllowInsecureLoopback = true
	if err := insecure.Validate(); err != nil {
		t.Fatalf("insecure loopback config must be valid: %v", err)
	}

	for _, tc := range []struct {
		name    string
		service *Service
		secure  bool
	}{
		{"https origin", New(db, safe, clock), true},
		{"insecure loopback", New(db, insecure, clock), false},
	} {
		h := mustEntrance(t, tc.service, testEntrancePath, http.NewServeMux())
		cookie := responseCookie(t, entranceDo(h, http.MethodGet, testEntrancePath), "axp_entrance")
		if cookie == nil {
			t.Fatalf("%s: cookie not issued", tc.name)
		}
		if cookie.Secure != tc.secure {
			t.Errorf("%s: Secure = %v, want %v", tc.name, cookie.Secure, tc.secure)
		}
	}
}
