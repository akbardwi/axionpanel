// Package auth implements panel authentication: argon2id password hashing,
// login lockout, cookie sessions with idle and absolute expiry, and CSRF
// protection for state-changing requests. This is the browser session flow
// from docs/spec.md §5.1; TOTP second factor and sudo mode are separate.
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
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// SessionCookie carries the raw session token. The database only ever stores
// its SHA-256 hash.
const SessionCookie = "axp_session"

// Argon2id parameters per the current OWASP guidance. The cost parameters are
// embedded in each hash string so they can be raised without invalidating
// existing passwords.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 19456 // KiB
	argonThreads uint8  = 1
	argonSaltLen        = 16
	argonKeyLen         = 32
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrLockedOut          = errors.New("auth: account temporarily locked")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrSessionExpired     = errors.New("auth: session expired")

	// dummyHash keeps unknown-username logins on the same cost path as real
	// ones so response timing cannot enumerate accounts.
	dummyHash, _ = HashPassword("axionpanel-timing-equalizer")
)

// Clock supplies the current time so tests can control expiry.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Config holds authentication policy. Zero values are not usable; start from
// DefaultConfig.
type Config struct {
	SessionIdleTTL     time.Duration // inactivity window
	SessionAbsoluteTTL time.Duration // hard cap from creation
	LockoutThreshold   int           // consecutive failures before lockout
	LockoutWindow      time.Duration // how long the lockout lasts
}

// DefaultConfig matches docs/spec.md §5.1: 2h idle, 24h absolute,
// 5 failures locking the account for 15 minutes.
func DefaultConfig() Config {
	return Config{
		SessionIdleTTL:     2 * time.Hour,
		SessionAbsoluteTTL: 24 * time.Hour,
		LockoutThreshold:   5,
		LockoutWindow:      15 * time.Minute,
	}
}

// User is a panel account. Secrets stay in the database and are never
// serialized.
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

// Session is a browser login. Token and CSRFToken are raw values returned only
// at creation; everything else is derived from stored hashes.
type Session struct {
	ID            int64
	UserID        int64
	User          User
	Token         string
	TokenHash     string
	CSRFToken     string
	CSRFTokenHash string
	IP            string
	UserAgent     string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
}

// Service owns authentication against the panel database.
type Service struct {
	db  *sql.DB
	cfg Config
	now Clock
}

// New returns a Service. A nil clock means the system clock.
func New(db *sql.DB, cfg Config, clock Clock) *Service {
	if clock == nil {
		clock = systemClock{}
	}
	return &Service{db: db, cfg: cfg, now: clock}
}

// HashPassword returns an argon2id hash in PHC string form.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	params := map[string]uint64{}
	for _, kv := range strings.Split(parts[2], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return false
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false
		}
		params[k] = n
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt,
		uint32(params["t"]), uint32(params["m"]), uint8(params["p"]), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Create registers a user with the given role.
func (s *Service) Create(ctx context.Context, username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("auth: username must not be empty")
	}
	if password == "" {
		return nil, errors.New("auth: password must not be empty")
	}
	switch role {
	case "admin", "reseller", "user":
	default:
		return nil, fmt.Errorf("auth: invalid role %q", role)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
		username, hash, role)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, errors.New("auth: username already exists")
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.userByID(ctx, id)
}

// Authenticate verifies a password, enforcing the failed-login lockout, and
// resets the failure counter on success.
func (s *Service) Authenticate(ctx context.Context, username, password, ip string) (*User, error) {
	u, err := s.userByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		VerifyPassword(dummyHash, password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	now := s.now.Now()
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return nil, ErrLockedOut
	}
	if !VerifyPassword(u.passwordHash, password) {
		if err := s.recordFailure(ctx, u, now); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ?, updated_at = ? WHERE id = ?`,
		fmtTime(now), fmtTime(now), u.ID); err != nil {
		return nil, err
	}
	u.FailedLogins = 0
	u.LockedUntil = nil
	u.LastLoginAt = &now
	return u, nil
}

func (s *Service) recordFailure(ctx context.Context, u *User, now time.Time) error {
	failed := u.FailedLogins + 1
	var lockedUntil any
	if failed >= s.cfg.LockoutThreshold {
		t := now.Add(s.cfg.LockoutWindow)
		lockedUntil = fmtTime(t)
		u.LockedUntil = &t
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?`,
		failed, lockedUntil, fmtTime(now), u.ID)
	u.FailedLogins = failed
	return err
}

// CreateSession issues a new login session for the user.
func (s *Service) CreateSession(ctx context.Context, userID int64, ip, userAgent string) (*Session, error) {
	token, err := randomToken("axp_", 32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken("", 32)
	if err != nil {
		return nil, err
	}
	now := s.now.Now()
	sess := &Session{
		UserID:        userID,
		Token:         token,
		TokenHash:     hashToken(token),
		CSRFToken:     csrf,
		CSRFTokenHash: hashToken(csrf),
		IP:            ip,
		UserAgent:     userAgent,
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(s.cfg.SessionAbsoluteTTL),
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions
		(token_hash, csrf_token_hash, user_id, ip, user_agent, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.CSRFTokenHash, sess.UserID, sess.IP, sess.UserAgent,
		fmtTime(sess.ExpiresAt), fmtTime(now), fmtTime(now))
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// Lookup resolves a session by its token hash, sliding the idle window. It
// purges and rejects sessions past either expiry.
func (s *Service) Lookup(ctx context.Context, tokenHash string) (*Session, error) {
	var (
		sess      Session
		created   string
		lastSeen  string
		expires   string
		agent     sql.NullString
		lockedRaw sql.NullString
		lastLogin sql.NullString
	)
	row := s.db.QueryRowContext(ctx, `SELECT
		s.id, s.user_id, s.csrf_token_hash, s.ip, s.user_agent,
		s.created_at, s.last_seen_at, s.expires_at,
		u.username, u.email, u.role, u.status, u.totp_enabled,
		u.failed_logins, u.locked_until, u.last_login_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, tokenHash)
	var email sql.NullString
	err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFTokenHash, &sess.IP, &agent,
		&created, &lastSeen, &expires,
		&sess.User.Username, &email, &sess.User.Role, &sess.User.Status, &sess.User.TOTPEnabled,
		&sess.User.FailedLogins, &lockedRaw, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.TokenHash = tokenHash
	sess.UserAgent = agent.String
	sess.User.ID = sess.UserID
	sess.User.Email = email.String
	sess.CreatedAt = parseTime(created)
	sess.LastSeenAt = parseTime(lastSeen)
	sess.ExpiresAt = parseTime(expires)
	sess.User.LockedUntil = parseNullTime(lockedRaw)
	sess.User.LastLoginAt = parseNullTime(lastLogin)

	now := s.now.Now()
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) >= s.cfg.SessionIdleTTL {
		// Expired: purge it and tell the caller it is gone.
		s.DeleteSession(ctx, tokenHash)
		return nil, ErrSessionExpired
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, fmtTime(now), sess.ID); err != nil {
		return nil, err
	}
	sess.LastSeenAt = now
	return &sess, nil
}

// DeleteSession revokes one session by token hash.
func (s *Service) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Service) userByID(ctx context.Context, id int64) (*User, error) {
	return s.userQuery(ctx, `SELECT`+userColumns+` FROM users WHERE id = ?`, id)
}

func (s *Service) userByUsername(ctx context.Context, username string) (*User, error) {
	// The column is COLLATE NOCASE, so this match is case-insensitive.
	return s.userQuery(ctx, `SELECT`+userColumns+` FROM users WHERE username = ?`, username)
}

const userColumns = ` id, username, COALESCE(email, ''), role, status, password_hash,
	totp_enabled, failed_logins, locked_until, last_login_at `

func (s *Service) userQuery(ctx context.Context, query string, arg any) (*User, error) {
	var (
		u         User
		lockedRaw sql.NullString
		lastLogin sql.NullString
	)
	err := s.db.QueryRowContext(ctx, query, arg).Scan(
		&u.ID, &u.Username, &u.Email, &u.Role, &u.Status, &u.passwordHash,
		&u.TOTPEnabled, &u.FailedLogins, &lockedRaw, &lastLogin)
	if err != nil {
		return nil, err
	}
	u.LockedUntil = parseNullTime(lockedRaw)
	u.LastLoginAt = parseNullTime(lastLogin)
	return &u, nil
}

// Register mounts the auth endpoints on mux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.Handle("POST /api/v1/auth/logout", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogout))))
	mux.Handle("GET /api/v1/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Request body must be JSON with username and password.")
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Username is required.", map[string]string{"username": "required"})
		return
	}
	u, err := s.Authenticate(r.Context(), req.Username, req.Password, clientIP(r))
	switch {
	case errors.Is(err, ErrLockedOut):
		writeError(w, http.StatusLocked, "locked_out", "Too many failed attempts. Try again later.")
	case err != nil:
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password.")
	default:
		sess, err := s.CreateSession(r.Context(), u.ID, clientIP(r), r.UserAgent())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Could not create a session.")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookie,
			Value:    sess.Token,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			Expires:  sess.ExpiresAt,
			MaxAge:   int(s.cfg.SessionAbsoluteTTL / time.Second),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"user":         u,
			"csrf_token":   sess.CSRFToken,
			"mfa_required": u.TOTPEnabled,
		})
	}
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if err := s.DeleteSession(r.Context(), sess.TokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Could not end the session.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": sessionFrom(r.Context()).User})
}

type ctxKey int

const sessionCtxKey ctxKey = 0

func sessionFrom(ctx context.Context) *Session {
	sess, _ := ctx.Value(sessionCtxKey).(*Session)
	return sess
}

// requireAuth resolves the session cookie into the request context.
func (s *Service) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
			return
		}
		sess, err := s.Lookup(r.Context(), hashToken(cookie.Value))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	})
}

// requireCSRF rejects state-changing requests without a matching CSRF token,
// and rejects mismatched browser origins where the header is present.
func (s *Service) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		presented := r.Header.Get("X-CSRF-Token")
		if presented == "" ||
			subtle.ConstantTimeCompare([]byte(hashToken(presented)), []byte(sess.CSRFTokenHash)) != 1 {
			writeError(w, http.StatusForbidden, "csrf", "Missing or invalid CSRF token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string, fields ...map[string]string) {
	// Spec shape: {"error":{"code","message","fields"}}. Fields stay empty
	// unless validation produced some.
	err := map[string]any{"code": code, "message": message}
	if len(fields) > 0 {
		err["fields"] = fields[0]
	}
	writeJSON(w, status, map[string]any{"error": err})
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// hashToken is one-way: raw tokens never reach the database.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewPassword generates a random password for first-run bootstrap.
func NewPassword() (string, error) {
	return randomToken("", 18)
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseNullTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTime(s.String)
	return &t
}
