// Package auth implements browser authentication, MFA and sudo authorization.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"axionpanel/internal/secret"
	"golang.org/x/crypto/argon2"
)

const SessionCookie = "axp_session"
const MFACookie = "axp_mfa"

// CSRFCookie exposes only the synchronizer token, never session credentials.
// The server still verifies the header against the session's stored hash.
const CSRFCookie = "axp_csrf"
const (
	argonTime         uint32 = 2
	argonMemory       uint32 = 19456
	argonThreads      uint8  = 1
	argonSaltLen             = 16
	argonKeyLen              = 32
	maxPassword              = 1024
	maxJSON                  = 8192
	challengeTTL             = 5 * time.Minute
	challengeAttempts        = 5
	sudoTTL                  = 10 * time.Minute
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrLockedOut          = errors.New("auth: account temporarily locked")
	ErrRateLimited        = errors.New("auth: IP temporarily blocked")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrSessionExpired     = errors.New("auth: session expired")
	errUnavailable        = errors.New("auth: MFA unavailable")
	dummyHash, _          = HashPassword("axionpanel-timing-equalizer")
	// Bound aggregate Argon2 allocation as well as individual PHC costs.
	passwordSlots = make(chan struct{}, 4)
)

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Config struct {
	SessionIdleTTL        time.Duration
	SessionAbsoluteTTL    time.Duration
	LockoutThreshold      int
	LockoutWindow         time.Duration
	Origin                string
	AllowInsecureLoopback bool
	TrustedProxies        []*net.IPNet
	IPFailureLimit        int
	MFAUserFailureLimit   int
}

func DefaultConfig() Config {
	return Config{SessionIdleTTL: 2 * time.Hour, SessionAbsoluteTTL: 24 * time.Hour,
		LockoutThreshold: 5, LockoutWindow: 15 * time.Minute, Origin: "https://localhost:7800",
		IPFailureLimit: 20, MFAUserFailureLimit: 5}
}

// Validate rejects ambiguous origins and HTTP except explicit loopback development.
func (c Config) Validate() error {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || c.Origin != u.Scheme+"://"+u.Host || strings.ToLower(u.Host) != u.Host {
		return errors.New("auth: invalid origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.AllowInsecureLoopback && loopbackHost(u.Hostname())) {
		return errors.New("auth: HTTPS origin required")
	}
	if u.Hostname() == "" || strings.ContainsAny(u.Host, "\\ \t\r\n") {
		return errors.New("auth: invalid origin host")
	}
	if c.SessionIdleTTL <= 0 || c.SessionAbsoluteTTL <= 0 || c.LockoutThreshold <= 0 || c.LockoutWindow <= 0 || c.IPFailureLimit <= 0 || c.MFAUserFailureLimit <= 0 {
		return errors.New("auth: invalid policy")
	}
	return nil
}
func loopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email,omitempty"`
	Role         string     `json:"role"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	Status       string     `json:"-"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"-"`
	passwordHash string
}
type Session struct {
	ID, UserID                                 int64
	User                                       User
	Token, TokenHash, CSRFToken, CSRFTokenHash string
	IP, UserAgent                              string
	CreatedAt, LastSeenAt, ExpiresAt           time.Time
	MFAPassed                                  bool
	SudoUntil                                  *time.Time
}
type Service struct {
	db  *sql.DB
	cfg Config
	now Clock
	box *secret.Box
}

func New(db *sql.DB, cfg Config, clock Clock) *Service {
	if clock == nil {
		clock = systemClock{}
	}
	return &Service{db: db, cfg: cfg, now: clock}
}

// WithSecretBox must be called during initialization, before serving requests.
// Non-MFA login works without it; all MFA operations fail closed.
func (s *Service) WithSecretBox(box *secret.Box) *Service { s.box = box; return s }

func HashPassword(password string) (string, error) {
	if len(password) == 0 || len(password) > maxPassword {
		return "", errors.New("auth: password must contain 1 to 1024 bytes")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	// dummyHash is initialized before passwordSlots; a nil channel is skipped.
	if passwordSlots != nil {
		passwordSlots <- struct{}{}
		defer func() { <-passwordSlots }()
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func VerifyPassword(encoded, password string) bool {
	if len(password) == 0 || len(password) > maxPassword || len(encoded) > 512 {
		return false
	}
	p := strings.Split(encoded, "$")
	if len(p) != 5 || p[0] != "argon2id" || p[1] != "v=19" {
		return false
	}
	params := map[string]uint64{}
	for _, pair := range strings.Split(p[2], ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || (k != "m" && k != "t" && k != "p") {
			return false
		}
		if _, exists := params[k]; exists {
			return false
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false
		}
		params[k] = n
	}
	m, t, threads := params["m"], params["t"], params["p"]
	if len(params) != 3 || t < 1 || t > 4 || threads < 1 || threads > 4 || m < 8*threads || m > 65536 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[3])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p[4])
	if err != nil || len(want) != 32 {
		return false
	}
	passwordSlots <- struct{}{}
	defer func() { <-passwordSlots }()
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (s *Service) Create(ctx context.Context, username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 {
		return nil, errors.New("auth: invalid username")
	}
	switch role {
	case "admin", "reseller", "user":
	default:
		return nil, errors.New("auth: invalid role")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username,password_hash,role) VALUES(?,?,?)`, username, hash, role)
	if err != nil {
		// Wrap the driver cause for operators/errors.As. SQLite messages name
		// constraints/columns, never bound values (password hash, username).
		// HTTP handlers must map this to a generic response.
		return nil, fmt.Errorf("auth: could not create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.userByID(ctx, id)
}

// writeTx acquires SQLite's writer reservation before reading. This avoids
// read-then-upgrade SQLITE_BUSY_SNAPSHOT races across separate panel processes.
func (s *Service) writeTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET id=id WHERE 0`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const userColumns = ` id,username,COALESCE(email,''),role,status,password_hash,totp_enabled,failed_logins,locked_until,last_login_at `

func userQuery(ctx context.Context, q querier, query string, arg any) (*User, error) {
	var u User
	var locked, last sql.NullString
	if err := q.QueryRowContext(ctx, query, arg).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Status, &u.passwordHash, &u.TOTPEnabled, &u.FailedLogins, &locked, &last); err != nil {
		return nil, err
	}
	u.LockedUntil = parseNullTime(locked)
	u.LastLoginAt = parseNullTime(last)
	return &u, nil
}
func (s *Service) userByID(ctx context.Context, id int64) (*User, error) {
	return userQuery(ctx, s.db, `SELECT`+userColumns+`FROM users WHERE id=?`, id)
}
func (s *Service) userByUsername(ctx context.Context, name string) (*User, error) {
	return userQuery(ctx, s.db, `SELECT`+userColumns+`FROM users WHERE username=?`, name)
}

// Authenticate validates the password, not the second factor. CreateSession
// intentionally never grants MFA; Lookup rejects it for MFA-enabled users.
//
// A failure is reserved before the Argon2 work (outside any DB transaction),
// so concurrent guesses cannot overshoot the limits; success refunds it.
func (s *Service) Authenticate(ctx context.Context, username, password, ip string) (*User, error) {
	return s.authenticate(ctx, username, password, ip, true)
}

// authenticate implements Authenticate. recordLogin=false is for in-session
// re-verification (sudo): throttling is identical, but users.last_login_at
// keeps the time of the real sign-in.
func (s *Service) authenticate(ctx context.Context, username, password, ip string, recordLogin bool) (*User, error) {
	if len(username) > 128 || len(password) > maxPassword {
		return nil, ErrInvalidCredentials
	}
	key := hashToken(strings.ToLower(username))
	u, err := s.reserveAttempt(ctx, username, key, ip)
	if err != nil {
		return nil, err
	}
	hash := dummyHash
	if u != nil {
		hash = u.passwordHash
	}
	valid := VerifyPassword(hash, password)
	if !valid || u == nil || u.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	now := s.now.Now()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_throttle WHERE scope='username' AND key=?`, key); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE auth_throttle SET failures=max(failures-1,0) WHERE scope='ip' AND key=?`, ipKey(ip)); err != nil {
		return nil, err
	}
	touch := 0
	if recordLogin {
		touch = 1
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET failed_logins=0,locked_until=NULL,last_login_at=CASE WHEN ?1 THEN ?2 ELSE last_login_at END,updated_at=?2 WHERE id=?3`, touch, fmtTime(now), u.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	u.FailedLogins = 0
	u.LockedUntil = nil
	if recordLogin {
		u.LastLoginAt = &now
	}
	return u, nil
}

// reserveAttempt enforces IP, username and account limits and records one
// pending failure. It returns a nil user for unknown usernames.
func (s *Service) reserveAttempt(ctx context.Context, username, key, ip string) (*User, error) {
	tx, err := s.writeTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now.Now()
	if err = s.checkLimits(ctx, tx, ip, "username", key, s.cfg.LockoutThreshold); err != nil {
		return nil, err
	}
	u, err := userQuery(ctx, tx, `SELECT`+userColumns+`FROM users WHERE username=?`, username)
	if errors.Is(err, sql.ErrNoRows) {
		u, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u != nil && u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return nil, ErrLockedOut
	}
	if err = s.failure(ctx, tx, ip, "username", key); err != nil {
		return nil, err
	}
	if u != nil {
		const next = `(CASE WHEN locked_until IS NOT NULL AND locked_until<=?1 THEN 1 ELSE failed_logins+1 END)`
		if _, err = tx.ExecContext(ctx, `UPDATE users SET failed_logins=`+next+`, locked_until=CASE WHEN `+next+`>=?2 THEN ?3 ELSE NULL END, updated_at=?1 WHERE id=?4`,
			fmtTime(now), s.cfg.LockoutThreshold, fmtTime(now.Add(s.cfg.LockoutWindow)), u.ID); err != nil {
			return nil, err
		}
	}
	return u, tx.Commit()
}
func (s *Service) checkLimits(ctx context.Context, tx *sql.Tx, ip, scope, key string, limit int) error {
	if s.throttled(ctx, tx, "ip", ipKey(ip), s.cfg.IPFailureLimit) {
		return ErrRateLimited
	}
	if s.throttled(ctx, tx, scope, key, limit) {
		return ErrLockedOut
	}
	return nil
}
func (s *Service) throttled(ctx context.Context, tx *sql.Tx, scope, key string, limit int) bool {
	var n int
	var start string
	err := tx.QueryRowContext(ctx, `SELECT failures,window_start FROM auth_throttle WHERE scope=? AND key=?`, scope, key).Scan(&n, &start)
	// DB failures fail closed rather than silently bypassing throttling.
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		return true
	}
	return n >= limit && s.now.Now().Before(parseTime(start).Add(s.cfg.LockoutWindow))
}

// failure counts one failed attempt against the client IP and scope/key in a
// fixed window of LockoutWindow.
func (s *Service) failure(ctx context.Context, tx *sql.Tx, ip, scope, key string) error {
	now := fmtTime(s.now.Now())
	old := fmtTime(s.now.Now().Add(-s.cfg.LockoutWindow))
	// Prune windows that can no longer block anyone so unknown-username
	// spraying cannot grow the table without bound.
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_throttle WHERE window_start<=?`, old); err != nil {
		return err
	}
	for _, v := range [][2]string{{"ip", ipKey(ip)}, {scope, key}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_throttle(scope,key,failures,window_start) VALUES(?1,?2,1,?3)
   ON CONFLICT(scope,key) DO UPDATE SET failures=CASE WHEN window_start<=?4 THEN 1 ELSE failures+1 END,
   window_start=CASE WHEN window_start<=?4 THEN ?3 ELSE window_start END`, v[0], v[1], now, old); err != nil {
			return err
		}
	}
	return nil
}

// ipKey groups IPv6 clients by /64 so one host cannot rotate addresses.
func ipKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return hashToken("unknown")
	}
	if v4 := parsed.To4(); v4 != nil {
		return hashToken(v4.String())
	}
	return hashToken(parsed.Mask(net.CIDRMask(64, 128)).String() + "/64")
}

func (s *Service) newSession(userID int64, ip, agent string) (*Session, error) {
	token, err := randomToken("axp_", 32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken("", 32)
	if err != nil {
		return nil, err
	}
	now := s.now.Now()
	return &Session{UserID: userID, Token: token, TokenHash: hashToken(token), CSRFToken: csrf, CSRFTokenHash: hashToken(csrf), IP: ip, UserAgent: bounded(agent, 512), CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.cfg.SessionAbsoluteTTL)}, nil
}
func insertSession(ctx context.Context, tx *sql.Tx, sess *Session) error {
	res, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,csrf_token_hash,user_id,ip,user_agent,expires_at,created_at,last_seen_at,mfa_passed) VALUES(?,?,?,?,?,?,?,?,?)`, sess.TokenHash, sess.CSRFTokenHash, sess.UserID, sess.IP, sess.UserAgent, fmtTime(sess.ExpiresAt), fmtTime(sess.CreatedAt), fmtTime(sess.LastSeenAt), sess.MFAPassed)
	if err != nil {
		return err
	}
	sess.ID, err = res.LastInsertId()
	return err
}
func (s *Service) CreateSession(ctx context.Context, userID int64, ip, agent string) (*Session, error) {
	sess, err := s.newSession(userID, ip, agent)
	if err != nil {
		return nil, err
	}
	tx, err := s.writeTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = insertSession(ctx, tx, sess); err != nil {
		return nil, err
	}
	return sess, tx.Commit()
}
func (s *Service) Lookup(ctx context.Context, tokenHash string) (*Session, error) {
	var sess Session
	var created, last, expires string
	var agent, ip, email, locked, login, sudo sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT s.id,s.user_id,s.csrf_token_hash,s.ip,s.user_agent,s.created_at,s.last_seen_at,s.expires_at,s.mfa_passed,s.sudo_until,u.username,u.email,u.role,u.status,u.totp_enabled,u.failed_logins,u.locked_until,u.last_login_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, tokenHash).Scan(&sess.ID, &sess.UserID, &sess.CSRFTokenHash, &ip, &agent, &created, &last, &expires, &sess.MFAPassed, &sudo, &sess.User.Username, &email, &sess.User.Role, &sess.User.Status, &sess.User.TOTPEnabled, &sess.User.FailedLogins, &locked, &login)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.TokenHash = tokenHash
	sess.IP = ip.String
	sess.UserAgent = agent.String
	sess.User.ID = sess.UserID
	sess.User.Email = email.String
	sess.CreatedAt = parseTime(created)
	sess.LastSeenAt = parseTime(last)
	sess.ExpiresAt = parseTime(expires)
	sess.SudoUntil = parseNullTime(sudo)
	sess.User.LockedUntil = parseNullTime(locked)
	sess.User.LastLoginAt = parseNullTime(login)
	if sess.User.Status != "active" || (sess.User.TOTPEnabled && !sess.MFAPassed) {
		return nil, ErrSessionNotFound
	}
	now := s.now.Now()
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) >= s.cfg.SessionIdleTTL {
		s.DeleteSession(ctx, tokenHash)
		return nil, ErrSessionExpired
	}
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE id=?`, fmtTime(now), sess.ID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil, ErrSessionNotFound
	}
	sess.LastSeenAt = now
	return &sess, nil
}
func (s *Service) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash)
	return err
}

func (s *Service) Register(mux *http.ServeMux) {
	post := func(path string, h http.HandlerFunc, authenticated bool) {
		var next http.Handler = h
		if authenticated {
			next = s.requireAuth(s.requireCSRF(next))
		}
		mux.Handle("POST /api/v1/auth/"+path, s.requireOrigin(next))
	}
	post("login", s.handleLogin, false)
	post("login/mfa", s.handleMFA, false)
	post("logout", s.handleLogout, true)
	post("reauth", s.handleReauth, true)
	post("mfa/setup", s.handleSetup, true)
	post("mfa/enable", s.handleEnable, true)
	post("mfa/disable", s.handleDisable, true)
	mux.Handle("GET /api/v1/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSON)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, 400, "invalid_request", "Invalid JSON request.")
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "invalid_request", "Invalid JSON request.")
		return false
	}
	return true
}
func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Username) == "" || len(req.Username) > 128 || len(req.Password) == 0 || len(req.Password) > maxPassword {
		writeError(w, 400, "invalid_request", "Invalid username or password length.")
		return
	}
	u, err := s.Authenticate(r.Context(), req.Username, req.Password, s.clientIP(r))
	if err != nil {
		authError(w, err)
		return
	}
	if u.TOTPEnabled {
		s.startChallenge(w, r, u)
		return
	}
	// Recheck MFA/status under the same write lock that creates the session.
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	fresh, err := userQuery(r.Context(), tx, `SELECT`+userColumns+`FROM users WHERE id=?`, u.ID)
	if err != nil || fresh.Status != "active" || fresh.TOTPEnabled {
		writeError(w, 401, "invalid_credentials", "Sign in again.")
		return
	}
	sess, err := s.newSession(u.ID, s.clientIP(r), r.UserAgent())
	if err == nil {
		err = insertSession(r.Context(), tx, sess)
	}
	if err == nil {
		err = revokePresented(r.Context(), tx, r)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w)
		return
	}
	s.setCookie(w, SessionCookie, sess.Token, sess.ExpiresAt, int(s.cfg.SessionAbsoluteTTL/time.Second))
	s.setCSRFCookie(w, sess.CSRFToken, sess.ExpiresAt, int(s.cfg.SessionAbsoluteTTL/time.Second))
	s.clearCookie(w, MFACookie)
	writeJSON(w, 200, map[string]any{"user": fresh, "csrf_token": sess.CSRFToken, "mfa_required": false})
}
func revokePresented(ctx context.Context, tx *sql.Tx, r *http.Request) error {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hashToken(c.Value)); err != nil {
			return err
		}
	}
	if c, err := r.Cookie(MFACookie); err == nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE token_hash=?`, hashToken(c.Value)); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) secureCookies() bool {
	u, err := url.Parse(s.cfg.Origin)
	return !(err == nil && u.Scheme == "http" && s.cfg.AllowInsecureLoopback && loopbackHost(u.Hostname()))
}
func (s *Service) setCookie(w http.ResponseWriter, name, value string, expires time.Time, age int) {
	path := "/"
	if name == MFACookie {
		path = "/api/v1/auth"
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: age})
}
func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	s.setCookie(w, name, "", time.Unix(1, 0), -1)
}

// setCSRFCookie publishes the synchronizer token to the UI after a full
// session exists. It carries no credentials; session and MFA cookies stay
// HttpOnly.
func (s *Service) setCSRFCookie(w http.ResponseWriter, csrf string, expires time.Time, age int) {
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: age})
}
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.DeleteSession(r.Context(), sessionFrom(r.Context()).TokenHash); err != nil {
		internalError(w)
		return
	}
	s.clearCookie(w, SessionCookie)
	s.clearCookie(w, MFACookie)
	s.clearCookie(w, CSRFCookie)
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	writeJSON(w, 200, map[string]any{"user": sess.User, "sudo_until": sess.SudoUntil})
}

type ctxKey int

const sessionCtxKey ctxKey = 0

// SessionFrom returns the session attached by RequireAuth, or nil.
func SessionFrom(ctx context.Context) *Session { return sessionFrom(ctx) }

// RequireAuth admits only requests with a valid, unexpired session cookie.
// It does not check CSRF; use it only for safe (GET) routes.
func (s *Service) RequireAuth(next http.Handler) http.Handler { return s.requireAuth(next) }

func sessionFrom(ctx context.Context) *Session {
	sess, _ := ctx.Value(sessionCtxKey).(*Session)
	return sess
}
func (s *Service) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" || len(c.Value) > 128 {
			writeError(w, 401, "unauthorized", "Sign in required.")
			return
		}
		sess, err := s.Lookup(r.Context(), hashToken(c.Value))
		if err != nil {
			writeError(w, 401, "unauthorized", "Sign in required.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	})
}
func (s *Service) requireOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Validate() != nil {
			internalError(w)
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) != 1 || origins[0] != s.cfg.Origin {
			writeError(w, 403, "origin", "Invalid request origin.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Service) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !csrfMatches(r, sessionFrom(r.Context()).CSRFTokenHash) {
			writeError(w, 403, "csrf", "Missing or invalid CSRF token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func csrfMatches(r *http.Request, want string) bool {
	values := r.Header.Values("X-CSRF-Token")
	return len(values) == 1 && len(values[0]) > 0 && len(values[0]) <= 128 && subtle.ConstantTimeCompare([]byte(hashToken(values[0])), []byte(want)) == 1
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string, fields ...map[string]string) {
	e := map[string]any{"code": code, "message": message}
	if len(fields) > 0 {
		e["fields"] = fields[0]
	}
	writeJSON(w, status, map[string]any{"error": e})
}
func internalError(w http.ResponseWriter) {
	writeError(w, 500, "internal", "Authentication could not be completed.")
}
func authError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLockedOut):
		writeError(w, 423, "locked_out", "Too many failed attempts. Try again later.")
	case errors.Is(err, ErrRateLimited):
		writeError(w, 429, "rate_limited", "Too many failed attempts. Try again later.")
	case errors.Is(err, errUnavailable):
		writeError(w, 503, "mfa_unavailable", "MFA is unavailable.")
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, errBadFactor), errors.Is(err, ErrSessionNotFound):
		writeError(w, 401, "invalid_credentials", "Invalid credentials.")
	default:
		internalError(w)
	}
}
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

// ParseTrustedProxies parses CIDR specs for reverse proxies whose forwarding
// headers may be trusted. Each must be a non-empty valid CIDR.
func ParseTrustedProxies(specs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(specs))
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			return nil, errors.New("auth: empty trusted proxy CIDR")
		}
		_, n, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid trusted proxy CIDR %q: %w", spec, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// clientIP resolves the client address, honouring forwarding headers only when
// the direct peer is a configured trusted proxy. Untrusted peers cannot spoof
// the client identity, so per-IP throttling and lockout stay per real client.
func (s *Service) clientIP(r *http.Request) string {
	ip := peerIP(r)
	if len(s.cfg.TrustedProxies) == 0 {
		return ip
	}
	peer := net.ParseIP(ip)
	if peer == nil || !ipIn(peer, s.cfg.TrustedProxies) {
		return ip
	}
	if cf := singleForwardedIP(r.Header.Values("CF-Connecting-IP")); cf != "" {
		return cf
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) != 1 {
		return ip
	}
	// Walk the X-Forwarded-For chain right to left, skipping configured trusted
	// hops; the first untrusted address is the client. A malformed hop before
	// the first untrusted address fails closed to the peer: the chain is
	// ambiguous, and skipping it would accept an attacker entry further left.
	for _, part := range reverse(strings.Split(xff[0], ",")) {
		c := net.ParseIP(strings.TrimSpace(part))
		if c == nil {
			return ip
		}
		if !ipIn(c, s.cfg.TrustedProxies) {
			return c.String()
		}
	}
	return ip
}

func singleForwardedIP(values []string) string {
	if len(values) != 1 {
		return ""
	}
	if ip := net.ParseIP(strings.TrimSpace(values[0])); ip != nil {
		return ip.String()
	}
	return ""
}

func reverse(parts []string) []string {
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func ipIn(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func randomToken(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
func NewPassword() (string, error) { return randomToken("", 18) }
func fmtTime(t time.Time) string   { return t.UTC().Format(time.RFC3339) }
func parseTime(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }
func parseNullTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTime(s.String)
	return &t
}
