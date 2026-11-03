package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"axionpanel/internal/secret"
	"axionpanel/internal/store"
	"axionpanel/internal/totp"
)

const testOrigin = "https://localhost:7800"

type mfaEnv struct {
	t     *testing.T
	s     *Service
	mux   *http.ServeMux
	clock *fakeClock
	db    *sql.DB
}

func newMFAEnv(t *testing.T, withBox bool, mutate ...func(*Config)) *mfaEnv {
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
	for _, m := range mutate {
		m(&cfg)
	}
	s := New(db, cfg, clock)
	if withBox {
		box, err := secret.LoadOrCreate(filepath.Join(t.TempDir(), "secret.key"))
		if err != nil {
			t.Fatalf("box: %v", err)
		}
		if s.WithSecretBox(box) != s {
			t.Fatal("WithSecretBox must return the service")
		}
	}
	mux := http.NewServeMux()
	s.Register(mux)
	if _, err := s.Create(context.Background(), "admin", "sekret-1", "admin"); err != nil {
		t.Fatalf("create: %v", err)
	}
	return &mfaEnv{t: t, s: s, mux: mux, clock: clock, db: db}
}

// client is a minimal cookie-jar browser bound to one remote address.
type client struct {
	env     *mfaEnv
	addr    string
	cookies map[string]*http.Cookie
	csrf    string
}

func (e *mfaEnv) client(addr string) *client {
	return &client{env: e, addr: addr, cookies: map[string]*http.Cookie{}}
}

type resp struct {
	code    int
	body    map[string]any
	raw     string
	cookies []*http.Cookie
}

func (r resp) errCode() string {
	e, _ := r.body["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (r resp) cookie(name string) *http.Cookie {
	for _, c := range r.cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (c *client) do(method, path, body string, hdr map[string]string) resp {
	req := httptest.NewRequest(method, "/api/v1/auth/"+path, strings.NewReader(body))
	req.RemoteAddr = c.addr
	if method == "POST" {
		req.Header.Set("Origin", testOrigin)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	rec := httptest.NewRecorder()
	c.env.mux.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.String(), cookies: rec.Result().Cookies()}
	json.Unmarshal(rec.Body.Bytes(), &out.body)
	for _, ck := range out.cookies {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	if tok, ok := out.body["csrf_token"].(string); ok && tok != "" {
		c.csrf = tok
	}
	return out
}

func (c *client) post(path, body string) resp { return c.do("POST", path, body, nil) }

func (c *client) login(t *testing.T) resp {
	t.Helper()
	r := c.post("login", `{"username":"admin","password":"sekret-1"}`)
	if r.code != 200 {
		t.Fatalf("login = %d %s", r.code, r.raw)
	}
	return r
}

func (e *mfaEnv) codeAt(secret string, at time.Time) string {
	code, err := totp.Code(secret, at, totp.Default)
	if err != nil {
		e.t.Fatalf("code: %v", err)
	}
	return code
}

func (e *mfaEnv) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// enroll logs c in, enters sudo, and enables MFA. It returns the TOTP secret
// and the recovery codes.
func (e *mfaEnv) enroll(c *client) (string, []string) {
	t := e.t
	t.Helper()
	c.login(t)
	if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 200 {
		t.Fatalf("reauth = %d %s", r.code, r.raw)
	}
	r := c.post("mfa/setup", `{}`)
	if r.code != 200 {
		t.Fatalf("setup = %d %s", r.code, r.raw)
	}
	sec := r.body["secret"].(string)
	r = c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
	if r.code != 200 {
		t.Fatalf("enable = %d %s", r.code, r.raw)
	}
	var codes []string
	for _, v := range r.body["recovery_codes"].([]any) {
		codes = append(codes, v.(string))
	}
	return sec, codes
}

func TestSessionCookieSecureByDefault(t *testing.T) {
	e := newMFAEnv(t, true)
	r := e.client("192.0.2.10:5000").login(t)
	ck := r.cookie(SessionCookie)
	if ck == nil || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v, want Secure HttpOnly SameSite=Strict even over plain HTTP", ck)
	}
}

func TestConfigValidation(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if DefaultConfig().Origin != "https://localhost:7800" || DefaultConfig().AllowInsecureLoopback {
		t.Fatal("defaults: Origin https://localhost:7800, AllowInsecureLoopback false")
	}
	bad := []Config{
		{Origin: "http://127.0.0.1:7800"},                                 // http without flag
		{Origin: "http://panel.example.com", AllowInsecureLoopback: true}, // http non-loopback
		{Origin: "https://panel.example.com/"},
		{Origin: "https://panel.example.com/x"},
		{Origin: "https://user@panel.example.com"},
		{Origin: "ftp://panel.example.com"},
		{Origin: ""},
		{Origin: "https://PANEL.example.com"},
	}
	for _, b := range bad {
		cfg := DefaultConfig()
		cfg.Origin, cfg.AllowInsecureLoopback = b.Origin, b.AllowInsecureLoopback
		if err := cfg.Validate(); err == nil {
			t.Errorf("config %+v must be invalid", b)
		}
	}
	// A misconfigured service fails closed.
	e := newMFAEnv(t, true, func(c *Config) { c.Origin = "http://panel.example.com" })
	if r := e.client("192.0.2.10:1").post("login", `{"username":"admin","password":"sekret-1"}`); r.code != 500 || r.cookie(SessionCookie) != nil {
		t.Fatalf("misconfigured login = %d, want 500 without a session", r.code)
	}
}

func TestInsecureLoopbackDevMode(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) {
		c.Origin = "http://127.0.0.1:7800"
		c.AllowInsecureLoopback = true
	})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"sekret-1"}`))
	req.Header.Set("Origin", "http://127.0.0.1:7800")
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == SessionCookie && ck.Secure {
			t.Fatal("explicit loopback dev mode must allow a non-Secure cookie")
		}
	}
}

func TestMFASetupRequiresRecentReauth(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.10:1")
	c.login(t)
	if r := c.post("mfa/setup", `{}`); r.code != 403 || r.errCode() != "sudo_required" {
		t.Fatalf("setup without sudo = %d %s", r.code, r.raw)
	}
	if r := c.post("reauth", `{"password":"wrong"}`); r.code != 403 {
		t.Fatalf("reauth wrong password = %d, want 403", r.code)
	}
	r := c.post("reauth", `{"password":"sekret-1"}`)
	if r.code != 200 || r.body["sudo_until"] == nil {
		t.Fatalf("reauth = %d %s", r.code, r.raw)
	}
	r = c.post("mfa/setup", `{}`)
	if r.code != 200 {
		t.Fatalf("setup = %d %s", r.code, r.raw)
	}
	sec, _ := r.body["secret"].(string)
	url, _ := r.body["otpauth_url"].(string)
	if len(sec) < 32 || !strings.HasPrefix(url, "otpauth://totp/AxionPanel:admin?") {
		t.Fatalf("setup body = %s", r.raw)
	}
	var active sql.NullString
	var pending string
	var enabled int
	e.db.QueryRow(`SELECT totp_secret_enc, totp_pending_secret_enc, totp_enabled FROM users`).Scan(&active, &pending, &enabled)
	if active.Valid || enabled != 0 {
		t.Error("setup must not touch the active secret or enable MFA")
	}
	if !strings.HasPrefix(pending, "v1:") || strings.Contains(pending, sec) {
		t.Error("pending secret must be stored encrypted")
	}
	// Sudo lasts 10 minutes.
	e.clock.advance(10*time.Minute + time.Second)
	if r := c.post("mfa/setup", `{}`); r.code != 403 {
		t.Fatalf("setup after sudo expiry = %d, want 403", r.code)
	}
}

func TestMFAEnable(t *testing.T) {
	e := newMFAEnv(t, true)
	other := e.client("192.0.2.11:1")
	other.login(t)
	c := e.client("192.0.2.10:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	sec := c.post("mfa/setup", `{}`).body["secret"].(string)

	if r := c.post("mfa/enable", `{"code":"000000"}`); r.code != 422 || r.errCode() != "invalid_mfa_code" {
		t.Fatalf("enable wrong code = %d %s", r.code, r.raw)
	}
	if r := c.post("mfa/enable", `{"code":"12345"}`); r.code != 422 {
		t.Fatalf("enable malformed code = %d", r.code)
	}
	r := c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
	if r.code != 200 {
		t.Fatalf("enable = %d %s", r.code, r.raw)
	}
	raw, _ := r.body["recovery_codes"].([]any)
	if len(raw) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(raw))
	}
	seen := map[string]bool{}
	for _, v := range raw {
		code := v.(string)
		norm := strings.ReplaceAll(code, "-", "")
		if len(norm)*5 < 128 || seen[norm] {
			t.Errorf("recovery code %q too short or duplicated", code)
		}
		seen[norm] = true
		if e.count(`SELECT count(*) FROM user_recovery_codes WHERE code_hash = ? OR code_hash = ?`, code, norm) != 0 {
			t.Error("recovery codes must be stored hashed")
		}
	}
	if n := e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NULL`); n != 10 {
		t.Errorf("stored recovery codes = %d, want 10", n)
	}
	if n := e.count(`SELECT count(*) FROM users WHERE totp_enabled = 1 AND totp_secret_enc LIKE 'v1:%' AND totp_pending_secret_enc IS NULL AND totp_last_step IS NOT NULL`); n != 1 {
		t.Error("enable must move pending secret to active and record the step")
	}
	if r := other.do("GET", "me", "", nil); r.code != 401 {
		t.Errorf("other password-only session after enable = %d, want 401", r.code)
	}
	me := c.do("GET", "me", "", nil)
	if me.code != 200 {
		t.Fatalf("current session after enable = %d", me.code)
	}
	if r := c.post("mfa/enable", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now.Add(30*time.Second)))); r.code != 409 {
		t.Errorf("second enable = %d, want 409", r.code)
	}
	if r := c.post("mfa/setup", `{}`); r.code != 409 {
		t.Errorf("setup while enabled = %d, want 409", r.code)
	}
}

func TestMFALoginFlow(t *testing.T) {
	e := newMFAEnv(t, true)
	sec, _ := e.enroll(e.client("192.0.2.10:1"))
	sessionsBefore := e.count(`SELECT count(*) FROM sessions`)

	c := e.client("192.0.2.20:1")
	r := c.login(t)
	if r.body["mfa_required"] != true || c.csrf == "" {
		t.Fatalf("login body = %s", r.raw)
	}
	if r.cookie(SessionCookie) != nil || r.body["user"] != nil {
		t.Fatal("MFA login must not issue a session or user before the second factor")
	}
	ch := r.cookie(MFACookie)
	if ch == nil || !ch.HttpOnly || !ch.Secure || ch.SameSite != http.SameSiteStrictMode || ch.MaxAge <= 0 || ch.MaxAge > 300 {
		t.Fatalf("challenge cookie = %+v", ch)
	}
	if e.count(`SELECT count(*) FROM sessions`) != sessionsBefore {
		t.Fatal("no session row before MFA")
	}
	if e.count(`SELECT count(*) FROM mfa_challenges WHERE token_hash = ?`, hashToken(ch.Value)) != 1 {
		t.Fatal("challenge must be persisted by hash")
	}

	// The enrollment code's step is burned: same code cannot be replayed.
	if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 401 {
		t.Fatalf("replayed code = %d, want 401", r.code)
	}
	e.clock.advance(30 * time.Second)
	saved := *c.cookies[MFACookie]
	r = c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now)))
	if r.code != 200 || r.cookie(SessionCookie) == nil {
		t.Fatalf("mfa = %d %s", r.code, r.raw)
	}
	if ck := r.cookie(MFACookie); ck == nil || ck.MaxAge >= 0 {
		t.Error("challenge cookie must be cleared")
	}
	tok := r.cookie(SessionCookie).Value
	if e.count(`SELECT count(*) FROM sessions WHERE token_hash = ? AND mfa_passed = 1`, hashToken(tok)) != 1 {
		t.Fatal("MFA session must have mfa_passed = 1")
	}
	if me := c.do("GET", "me", "", nil); me.code != 200 {
		t.Fatalf("me = %d", me.code)
	}
	// Challenge is single use.
	replay := e.client("192.0.2.20:1")
	replay.cookies[MFACookie] = &saved
	replay.csrf = r.body["csrf_token"].(string)
	e.clock.advance(30 * time.Second)
	if r := replay.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 401 {
		t.Fatalf("challenge reuse = %d, want 401", r.code)
	}
}

func TestMFAChallengeGuards(t *testing.T) {
	e := newMFAEnv(t, true)
	sec, _ := e.enroll(e.client("192.0.2.10:1"))
	e.clock.advance(30 * time.Second)

	c := e.client("192.0.2.20:1")
	c.login(t)
	good := fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))
	if r := c.do("POST", "login/mfa", good, map[string]string{"X-CSRF-Token": "nope"}); r.code != 403 {
		t.Errorf("bad csrf = %d, want 403", r.code)
	}
	if r := c.do("POST", "login/mfa", good, map[string]string{"X-CSRF-Token": ""}); r.code != 403 {
		t.Errorf("missing csrf = %d, want 403", r.code)
	}
	if r := c.do("POST", "login/mfa", good, map[string]string{"Origin": "https://evil.test"}); r.code != 403 {
		t.Errorf("bad origin = %d, want 403", r.code)
	}
	if r := c.post("login/mfa", `{"code":"123456","recovery_code":"x"}`); r.code != 400 {
		t.Errorf("both factors = %d, want 400", r.code)
	}
	if r := e.client("192.0.2.20:1").post("login/mfa", good); r.code != 401 {
		t.Errorf("no challenge cookie = %d, want 401", r.code)
	}

	// Expiry: 5 minutes.
	e.clock.advance(5*time.Minute + time.Second)
	if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 401 {
		t.Errorf("expired challenge = %d, want 401", r.code)
	}
}

func TestMFAChallengeAttemptLimit(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.MFAUserFailureLimit = 100 })
	sec, _ := e.enroll(e.client("192.0.2.10:1"))
	e.clock.advance(30 * time.Second)
	c := e.client("192.0.2.20:1")
	c.login(t)
	for i := 0; i < 5; i++ {
		if r := c.post("login/mfa", `{"code":"000000"}`); r.code != 401 {
			t.Fatalf("wrong code %d = %d", i, r.code)
		}
	}
	if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 401 {
		t.Fatalf("correct code after attempt limit = %d, want 401", r.code)
	}
}

func TestMFAUserFailureLimitAcrossChallenges(t *testing.T) {
	e := newMFAEnv(t, true)
	sec, _ := e.enroll(e.client("192.0.2.10:1"))
	e.clock.advance(30 * time.Second)
	for i := 0; i < 5; i++ {
		c := e.client(fmt.Sprintf("198.51.100.%d:1", i))
		c.login(t)
		c.post("login/mfa", `{"code":"000000"}`)
	}
	c := e.client("198.51.100.99:1")
	c.login(t)
	if r := c.post("login/mfa", fmt.Sprintf(`{"code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 423 {
		t.Fatalf("correct code while MFA-locked = %d %s, want 423", r.code, r.raw)
	}
}

func TestRecoveryCodeLogin(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.10:1"))
	c := e.client("192.0.2.20:1")
	c.login(t)
	// Normalization: lowercase, no separators.
	alt := strings.ToLower(strings.ReplaceAll(codes[0], "-", ""))
	r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, alt))
	if r.code != 200 || r.cookie(SessionCookie) == nil {
		t.Fatalf("recovery login = %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 1 {
		t.Fatal("recovery code must be marked used")
	}
	c2 := e.client("192.0.2.21:1")
	c2.login(t)
	if r := c2.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 401 {
		t.Fatalf("reused recovery code = %d, want 401", r.code)
	}
}

func TestRecoveryCodeConcurrentConsumption(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.MFAUserFailureLimit = 1000 })
	_, codes := e.enroll(e.client("192.0.2.10:1"))
	const n = 12
	clients := make([]*client, n)
	for i := range clients {
		clients[i] = e.client(fmt.Sprintf("203.0.113.%d:1", i+1))
		clients[i].login(t)
	}
	var wg sync.WaitGroup
	results := make([]int, n)
	start := make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = clients[i].post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[3])).code
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, code := range results {
		if code == 200 {
			ok++
		} else if code != 401 {
			t.Errorf("unexpected status %d", code)
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent recovery successes = %d (%v), want exactly 1", ok, results)
	}
}

func TestConcurrentChallengeSingleUse(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) { c.MFAUserFailureLimit = 1000 })
	_, codes := e.enroll(e.client("192.0.2.10:1"))
	c := e.client("192.0.2.20:1")
	c.login(t)
	var wg sync.WaitGroup
	results := make([]int, len(codes))
	start := make(chan struct{})
	for i, code := range codes {
		wg.Add(1)
		go func(i int, code string) {
			defer wg.Done()
			cl := e.client("192.0.2.20:1")
			cl.cookies[MFACookie] = c.cookies[MFACookie]
			cl.csrf = c.csrf
			<-start
			results[i] = cl.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, code)).code
		}(i, code)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, r := range results {
		if r == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("one challenge produced %d sessions (%v), want 1", ok, results)
	}
	if n := e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`); n != 1 {
		t.Fatalf("recovery codes consumed = %d, want 1 (losers must not burn codes)", n)
	}
}

func TestPasswordOnlySessionRejectedForMFAAccount(t *testing.T) {
	e := newMFAEnv(t, true)
	e.enroll(e.client("192.0.2.10:1"))
	var id int64
	e.db.QueryRow(`SELECT id FROM users`).Scan(&id)
	sess, err := e.s.CreateSession(context.Background(), id, "192.0.2.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Lookup(context.Background(), hashToken(sess.Token)); err == nil {
		t.Fatal("password-only session must not resolve for an MFA account")
	}
}

func TestReauthWithMFA(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.10:1")
	sec, codes := e.enroll(c)
	e.clock.advance(11 * time.Minute)
	if r := c.post("reauth", `{"password":"sekret-1"}`); r.code != 403 {
		t.Fatalf("reauth without factor = %d, want 403", r.code)
	}
	code := e.codeAt(sec, e.clock.now)
	if r := c.post("reauth", fmt.Sprintf(`{"password":"wrong","code":%q}`, code)); r.code != 403 {
		t.Fatalf("reauth wrong password = %d, want 403", r.code)
	}
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","code":%q}`, code)); r.code != 200 {
		t.Fatalf("reauth = %d %s", r.code, r.raw)
	}
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","code":%q}`, code)); r.code != 403 {
		t.Fatalf("replayed reauth code = %d, want 403", r.code)
	}
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","recovery_code":%q}`, codes[1])); r.code != 200 {
		t.Fatalf("reauth with recovery = %d %s", r.code, r.raw)
	}
}

func TestMFADisable(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.10:1")
	sec, codes := e.enroll(c)
	e.clock.advance(30 * time.Second)
	other := e.client("192.0.2.30:1")
	other.login(t)
	if r := other.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 200 {
		t.Fatalf("other mfa = %d", r.code)
	}
	pending := e.client("192.0.2.31:1")
	pending.login(t)

	e.clock.advance(11 * time.Minute)
	if r := c.post("mfa/disable", `{}`); r.code != 403 || r.errCode() != "sudo_required" {
		t.Fatalf("disable without sudo = %d %s", r.code, r.raw)
	}
	if r := c.post("reauth", fmt.Sprintf(`{"password":"sekret-1","code":%q}`, e.codeAt(sec, e.clock.now))); r.code != 200 {
		t.Fatalf("reauth = %d %s", r.code, r.raw)
	}
	if r := c.post("mfa/disable", `{}`); r.code != 200 {
		t.Fatalf("disable = %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM users WHERE totp_enabled = 0 AND totp_secret_enc IS NULL AND totp_pending_secret_enc IS NULL AND totp_last_step IS NULL`) != 1 {
		t.Error("disable must clear all TOTP state")
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes`) != 0 || e.count(`SELECT count(*) FROM mfa_challenges`) != 0 {
		t.Error("disable must delete recovery codes and challenges")
	}
	if r := other.do("GET", "me", "", nil); r.code != 401 {
		t.Error("disable must revoke other sessions")
	}
	if r := c.do("GET", "me", "", nil); r.code != 200 {
		t.Error("current session must survive disable")
	}
	if r := pending.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[2])); r.code != 401 {
		t.Error("outstanding challenges must die with disable")
	}
	if r := e.client("192.0.2.40:1").login(t); r.body["mfa_required"] != false {
		t.Error("login after disable must not require MFA")
	}
}

func TestFailClosedWithoutSecretBox(t *testing.T) {
	e := newMFAEnv(t, false)
	c := e.client("192.0.2.10:1")
	c.login(t)
	c.post("reauth", `{"password":"sekret-1"}`)
	if r := c.post("mfa/setup", `{}`); r.code != 503 {
		t.Fatalf("setup without box = %d, want 503", r.code)
	}
	mustExec(t, e.s, `UPDATE users SET totp_secret_enc = 'v1:AAAA', totp_enabled = 1`)
	before := e.count(`SELECT count(*) FROM sessions`)
	r := e.client("192.0.2.11:1").post("login", `{"username":"admin","password":"sekret-1"}`)
	if r.code != 503 || r.cookie(SessionCookie) != nil || r.cookie(MFACookie) != nil {
		t.Fatalf("MFA login without box = %d %s", r.code, r.raw)
	}
	if e.count(`SELECT count(*) FROM sessions`) != before || e.count(`SELECT count(*) FROM mfa_challenges`) != 0 {
		t.Fatal("no session or challenge without box")
	}
}

func TestIPRateLimitIncludesUnknownUsers(t *testing.T) {
	e := newMFAEnv(t, true)
	attacker := e.client("198.51.100.7:4444")
	for i := 0; i < 20; i++ {
		r := attacker.do("POST", "login", fmt.Sprintf(`{"username":"ghost%d","password":"x"}`, i),
			map[string]string{"X-Forwarded-For": fmt.Sprintf("10.0.0.%d", i), "X-Real-IP": "10.9.9.9"})
		if r.code != 401 {
			t.Fatalf("attempt %d = %d", i, r.code)
		}
	}
	if r := attacker.post("login", `{"username":"admin","password":"sekret-1"}`); r.code != 429 {
		t.Fatalf("blocked IP correct login = %d, want 429", r.code)
	}
	if r := e.client("198.51.100.8:1").post("login", `{"username":"admin","password":"sekret-1"}`); r.code != 200 {
		t.Fatalf("other IP = %d, want 200", r.code)
	}
	e.clock.advance(16 * time.Minute)
	if r := attacker.post("login", `{"username":"admin","password":"sekret-1"}`); r.code != 200 {
		t.Fatalf("after block window = %d, want 200", r.code)
	}
}

func TestUnknownUserLockoutMatchesKnown(t *testing.T) {
	e := newMFAEnv(t, true)
	for _, name := range []string{"admin", "nobody"} {
		var last int
		for i := 0; i < 6; i++ {
			c := e.client(fmt.Sprintf("192.0.2.%d:1", 50+i))
			last = c.post("login", fmt.Sprintf(`{"username":%q,"password":"wrong"}`, name)).code
		}
		if last != 423 {
			t.Errorf("%s: sixth failure = %d, want 423", name, last)
		}
	}
}

func TestInputBounds(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.10:1")
	cases := map[string]string{
		"huge body":     `{"username":"admin","password":"` + strings.Repeat("a", 64<<10) + `"}`,
		"long password": `{"username":"admin","password":"` + strings.Repeat("a", 1025) + `"}`,
		"long username": `{"username":"` + strings.Repeat("a", 129) + `","password":"x"}`,
		"unknown field": `{"username":"admin","password":"sekret-1","admin":true}`,
		"trailing data": `{"username":"admin","password":"sekret-1"}{}`,
		"not json":      `username=admin`,
		"wrong type":    `{"username":1,"password":"x"}`,
	}
	for name, body := range cases {
		r := c.post("login", body)
		if r.code != 400 && r.code != 413 {
			t.Errorf("%s = %d, want 400/413", name, r.code)
		}
		if strings.Contains(r.raw, "json:") || strings.Contains(r.raw, "sql") {
			t.Errorf("%s leaks internals: %s", name, r.raw)
		}
	}
	if e.count(`SELECT failed_logins FROM users`) != 0 {
		t.Error("rejected input must not reach password verification")
	}
	if _, err := e.s.Create(context.Background(), "big", strings.Repeat("a", 1025), "admin"); err == nil {
		t.Error("Create must bound password size")
	}
}

func TestSuspendedUserCannotCompleteMFA(t *testing.T) {
	e := newMFAEnv(t, true)
	_, codes := e.enroll(e.client("192.0.2.10:1"))
	c := e.client("192.0.2.20:1")
	c.login(t)
	mustExec(t, e.s, `UPDATE users SET status = 'suspended'`)
	if r := c.post("login/mfa", fmt.Sprintf(`{"recovery_code":%q}`, codes[0])); r.code != 401 {
		t.Fatalf("suspended mfa = %d, want 401", r.code)
	}
	if e.count(`SELECT count(*) FROM user_recovery_codes WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("suspended user must not burn recovery codes")
	}
}

func TestLoginRotatesExistingSession(t *testing.T) {
	e := newMFAEnv(t, true)
	c := e.client("192.0.2.10:1")
	first := c.login(t).cookie(SessionCookie).Value
	c.login(t)
	if _, err := e.s.Lookup(context.Background(), hashToken(first)); err == nil {
		t.Fatal("login must revoke the session cookie it replaces")
	}
}
