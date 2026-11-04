package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"axionpanel/internal/totp"
)

var errBadFactor = errors.New("auth: invalid second factor")

// maxChallengesPerUser caps concurrent pending MFA logins per account.
const maxChallengesPerUser = 5

func isAuthOutcome(err error) bool {
	return errors.Is(err, errBadFactor) || errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrLockedOut) || errors.Is(err, ErrSessionNotFound)
}

func mfaKey(userID int64) string { return fmt.Sprintf("u:%d", userID) }

// recordMFAFailure throttles second-factor guessing per user. Callers run it
// only under the write lock, after the attempt has been burned.
func (s *Service) recordMFAFailure(ctx context.Context, tx *sql.Tx, ip string, userID int64) error {
	return s.failure(ctx, tx, ip, "mfa_user", mfaKey(userID))
}

func (s *Service) mfaLimited(ctx context.Context, tx *sql.Tx, userID int64) bool {
	return s.throttled(ctx, tx, "mfa_user", mfaKey(userID), s.cfg.MFAUserFailureLimit)
}

// startChallenge issues the short-lived MFA challenge after a verified
// password. No session exists yet: only the hashed challenge row and the
// HttpOnly cookie whose raw token is never stored.
func (s *Service) startChallenge(w http.ResponseWriter, r *http.Request, u *User) {
	if s.box == nil {
		authError(w, errUnavailable)
		return
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	token, err := randomToken("axp_mfa_", 32)
	if err != nil {
		internalError(w)
		return
	}
	csrf, err := randomToken("", 32)
	if err != nil {
		internalError(w)
		return
	}
	now := s.now.Now()
	// Opportunistic cleanup; a user may hold several challenges (one per
	// browser), each single use and bound to its own cookie.
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM mfa_challenges WHERE expires_at<=?`, fmtTime(now)); err != nil {
		internalError(w)
		return
	}
	// Bound outstanding challenges per user: keep the newest few so a
	// password holder cannot grow the table without limit.
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM mfa_challenges WHERE user_id=?1 AND id NOT IN
		(SELECT id FROM mfa_challenges WHERE user_id=?1 ORDER BY id DESC LIMIT ?2)`, u.ID, maxChallengesPerUser-1); err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO mfa_challenges(token_hash,csrf_token_hash,user_id,ip,user_agent,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		hashToken(token), hashToken(csrf), u.ID, s.clientIP(r), bounded(r.UserAgent(), 512), fmtTime(now), fmtTime(now.Add(challengeTTL))); err != nil {
		internalError(w)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	s.setCookie(w, MFACookie, token, now.Add(challengeTTL), int(challengeTTL/time.Second))
	writeJSON(w, 200, map[string]any{"mfa_required": true, "csrf_token": csrf})
}

// finishChallenge validates code or recovery_code against the single-use
// challenge and returns the user. Every submission burns an attempt; the
// challenge dies after challengeAttempts or its 5 minute deadline.
func (s *Service) finishChallenge(ctx context.Context, tx *sql.Tx, tokenHash, code, recovery, ip string) (*User, error) {
	now := s.now.Now()
	var (
		id, attempts int
		userID       int64
		expires      string
	)
	err := tx.QueryRowContext(ctx, `SELECT id,user_id,attempts,expires_at FROM mfa_challenges WHERE token_hash=?`, tokenHash).
		Scan(&id, &userID, &attempts, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.mfaLimited(ctx, tx, userID) {
		tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
		return nil, ErrLockedOut
	}
	if !now.Before(parseTime(expires)) || attempts >= challengeAttempts {
		tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
		return nil, ErrInvalidCredentials
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET attempts=attempts+1 WHERE id=?`, id); err != nil {
		return nil, err
	}
	u, err := userQuery(ctx, tx, `SELECT`+userColumns+`FROM users WHERE id=?`, userID)
	if err != nil {
		return nil, err
	}
	if u.Status != "active" || !u.TOTPEnabled {
		tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
		return nil, ErrInvalidCredentials
	}
	ok := false
	if recovery != "" {
		ok, err = s.consumeRecovery(ctx, tx, u.ID, recovery)
	} else {
		ok, err = s.consumeCode(ctx, tx, u, code)
	}
	if err != nil {
		tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
		return nil, err
	}
	if !ok {
		if err := s.recordMFAFailure(ctx, tx, ip, u.ID); err != nil {
			return nil, err
		}
		if s.mfaLimited(ctx, tx, u.ID) {
			tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
		}
		return nil, errBadFactor
	}
	// Single use: the delete must consume exactly one row.
	res, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("auth: challenge delete result: %w", err)
	}
	if n != 1 {
		// The challenge existed under this write lock. Losing it now is a
		// storage anomaly, not an auth outcome: callers must roll back the
		// already consumed factor and attempt.
		return nil, fmt.Errorf("auth: challenge delete affected %d rows, want 1", n)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_throttle WHERE scope='mfa_user' AND key=?`, mfaKey(u.ID)); err != nil {
		return nil, err
	}
	return u, nil
}

// consumeCode checks the TOTP code and persists the matched step so the same
// code can never authenticate twice (a step <= the stored one is a replay).
func (s *Service) consumeCode(ctx context.Context, tx *sql.Tx, u *User, code string) (bool, error) {
	if s.box == nil {
		return false, errUnavailable
	}
	if len(code) != totp.Default.Digits {
		return false, nil
	}
	var enc sql.NullString
	var lastStep sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT totp_secret_enc,totp_last_step FROM users WHERE id=?`, u.ID).Scan(&enc, &lastStep); err != nil {
		return false, err
	}
	if !enc.Valid {
		return false, errUnavailable
	}
	secretValue, err := s.box.Open(enc.String)
	if err != nil {
		return false, errUnavailable
	}
	step, ok := totp.Match(secretValue, code, s.now.Now(), totp.Default, 1)
	if !ok {
		return false, nil
	}
	if lastStep.Valid && step <= lastStep.Int64 {
		return false, nil // replay of an already used step
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET totp_last_step=? WHERE id=?`, step, u.ID)
	return err == nil, err
}

// consumeRecovery marks one unused recovery code as used. The conditional
// UPDATE is the concurrency gate: under the serialized write lock exactly one
// caller wins, so a code can never mint two sessions.
func (s *Service) consumeRecovery(ctx context.Context, tx *sql.Tx, userID int64, code string) (bool, error) {
	norm := normalizeRecovery(code)
	if norm == "" || len(norm) > 32 {
		return false, nil
	}
	res, err := tx.ExecContext(ctx, `UPDATE user_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		fmtTime(s.now.Now()), userID, hashToken(norm))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("auth: recovery code update result: %w", err)
	}
	return n == 1, nil
}

// normalizeRecovery lowercases the code and drops display separators.
func normalizeRecovery(code string) string {
	return strings.ToLower(strings.Join(strings.FieldsFunc(code, func(r rune) bool { return r == '-' || r == ' ' }), ""))
}

func (s *Service) handleMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if (req.Code == "") == (req.RecoveryCode == "") || len(req.Code) > 8 || len(req.RecoveryCode) > 64 {
		writeError(w, 400, "invalid_request", "Provide either code or recovery_code.")
		return
	}
	ch, err := r.Cookie(MFACookie)
	if err != nil || ch.Value == "" || len(ch.Value) > 128 {
		writeError(w, 401, "mfa_challenge", "Sign in again.")
		return
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	// The challenge carries the CSRF token issued at login; the client must
	// echo it in the header as for every state-changing request.
	var wantCSRF sql.NullString
	err = tx.QueryRowContext(r.Context(), `SELECT csrf_token_hash FROM mfa_challenges WHERE token_hash=?`, hashToken(ch.Value)).Scan(&wantCSRF)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 401, "mfa_challenge", "Sign in again.")
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	if !csrfMatches(r, wantCSRF.String) {
		writeError(w, 403, "csrf", "Missing or invalid CSRF token.")
		return
	}
	if s.box == nil {
		authError(w, errUnavailable)
		return
	}
	if s.throttled(r.Context(), tx, "ip", ipKey(s.clientIP(r)), s.cfg.IPFailureLimit) {
		authError(w, ErrRateLimited)
		return
	}
	u, err := s.finishChallenge(r.Context(), tx, hashToken(ch.Value), req.Code, req.RecoveryCode, s.clientIP(r))
	if err != nil {
		// Only expected authentication outcomes persist (burned attempt,
		// throttle, deleted challenge). Anything else rolls back so a
		// half-finished request never consumes a recovery code or TOTP step.
		if !isAuthOutcome(err) {
			authError(w, err)
			return
		}
		if commitErr := tx.Commit(); commitErr != nil {
			internalError(w)
			return
		}
		authError(w, err)
		return
	}
	sess, err := s.newSession(u.ID, s.clientIP(r), r.UserAgent())
	if err != nil {
		internalError(w)
		return
	}
	sess.MFAPassed = true
	if err := insertSession(r.Context(), tx, sess); err != nil {
		internalError(w)
		return
	}
	if err := revokePresented(r.Context(), tx, r); err != nil {
		internalError(w)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	s.setCookie(w, SessionCookie, sess.Token, sess.ExpiresAt, int(s.cfg.SessionAbsoluteTTL/time.Second))
	s.setCSRFCookie(w, sess.CSRFToken, sess.ExpiresAt, int(s.cfg.SessionAbsoluteTTL/time.Second))
	s.clearCookie(w, MFACookie)
	writeJSON(w, 200, map[string]any{"user": u, "csrf_token": sess.CSRFToken, "mfa_required": false})
}

// requireSudo gates security-sensitive actions on password re-authentication
// within the last sudoTTL. MFA users must re-prove the second factor too.
func (s *Service) requireSudo(w http.ResponseWriter, sess *Session) bool {
	if sess.SudoUntil == nil || !s.now.Now().Before(*sess.SudoUntil) {
		writeError(w, 403, "sudo_required", "Recent password verification required.")
		return false
	}
	return true
}

// sudoTx opens the write transaction for a sudo-only mutation and re-checks,
// under the lock, that the session still exists, its user is active, its MFA
// state is satisfied and sudo has not expired. The request-time Lookup alone
// would leave a check-then-act window.
func (s *Service) sudoTx(w http.ResponseWriter, r *http.Request) (*sql.Tx, *Session, bool) {
	sess := sessionFrom(r.Context())
	if !s.requireSudo(w, sess) {
		return nil, nil, false
	}
	if s.box == nil {
		authError(w, errUnavailable)
		return nil, nil, false
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return nil, nil, false
	}
	var status string
	var enabled, passed bool
	var sudo sql.NullString
	err = tx.QueryRowContext(r.Context(), `SELECT u.status,u.totp_enabled,s.mfa_passed,s.sudo_until FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.token_hash=?`, sess.ID, sess.TokenHash).Scan(&status, &enabled, &passed, &sudo)
	if err != nil || status != "active" || (enabled && !passed) {
		tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			internalError(w)
		} else {
			writeError(w, 401, "unauthorized", "Sign in required.")
		}
		return nil, nil, false
	}
	if until := parseNullTime(sudo); until == nil || !s.now.Now().Before(*until) {
		tx.Rollback()
		writeError(w, 403, "sudo_required", "Recent password verification required.")
		return nil, nil, false
	}
	if s.mfaLimited(r.Context(), tx, sess.UserID) {
		tx.Rollback()
		authError(w, ErrLockedOut)
		return nil, nil, false
	}
	return tx, sess, true
}

func (s *Service) handleReauth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !decode(w, r, &req) {
		return
	}
	sess := sessionFrom(r.Context())
	if len(req.Password) == 0 || len(req.Password) > maxPassword || len(req.Code) > 8 || len(req.RecoveryCode) > 64 {
		writeError(w, 400, "invalid_request", "Invalid re-authentication input.")
		return
	}
	// Re-verification is not a new sign-in: keep users.last_login_at.
	u, err := s.authenticate(r.Context(), sess.User.Username, req.Password, s.clientIP(r), false)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeError(w, 403, "invalid_credentials", "Invalid credentials.")
		} else {
			authError(w, err)
		}
		return
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	// Revalidate the session's full identity under the write lock, before any
	// factor consumption. The middleware Lookup ran outside this transaction;
	// a concurrent logout/deletion followed by SQLite row-ID reuse could point
	// sess.ID at a row now owned by a different token or user. Binding
	// id+token_hash+user_id and re-checking expiry/MFA state here closes the
	// check-then-act window that the slow Argon2 in authenticate opened.
	var (
		status   string
		enabled  bool
		passed   bool
		expires  string
		lastSeen string
	)
	err = tx.QueryRowContext(r.Context(), `SELECT u.status,u.totp_enabled,s.mfa_passed,s.expires_at,s.last_seen_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.token_hash=? AND s.user_id=?`, sess.ID, sess.TokenHash, sess.UserID).Scan(&status, &enabled, &passed, &expires, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		authError(w, ErrSessionNotFound)
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	now := s.now.Now()
	if status != "active" || u.ID != sess.UserID || (enabled && !passed) || !now.Before(parseTime(expires)) || now.Sub(parseTime(lastSeen)) >= s.cfg.SessionIdleTTL {
		authError(w, ErrSessionNotFound)
		return
	}
	// Gate the second factor on the freshly loaded totp_enabled, not the
	// snapshot u.TOTPEnabled returned by authenticate, so a concurrent
	// enable/disable between authenticate and this write lock cannot bypass
	// or wrongly demand the factor.
	if enabled {
		if (req.Code == "") == (req.RecoveryCode == "") {
			writeError(w, 403, "sudo_required", "Second factor required.")
			return
		}
		if s.box == nil {
			authError(w, errUnavailable)
			return
		}
		if s.mfaLimited(r.Context(), tx, u.ID) {
			authError(w, ErrLockedOut)
			return
		}
		var ok bool
		if req.RecoveryCode != "" {
			ok, err = s.consumeRecovery(r.Context(), tx, u.ID, req.RecoveryCode)
		} else {
			ok, err = s.consumeCode(r.Context(), tx, u, req.Code)
		}
		if err != nil {
			// Internal failure (unopenable secret, DB error): roll back so no
			// MFA budget or factor is consumed. 5xx, never an auth verdict.
			authError(w, err)
			return
		}
		if !ok {
			// Legitimate rejection: the guess burns one MFA failure and the
			// write must persist before the verdict is sent.
			if recErr := s.recordMFAFailure(r.Context(), tx, s.clientIP(r), u.ID); recErr != nil {
				internalError(w)
				return
			}
			if commitErr := tx.Commit(); commitErr != nil {
				internalError(w)
				return
			}
			writeError(w, 403, "sudo_required", "Second factor required.")
			return
		}
	} else if req.Code != "" || req.RecoveryCode != "" {
		writeError(w, 400, "invalid_request", "Second factor not configured.")
		return
	}
	until := s.now.Now().Add(sudoTTL)
	// Bind full identity (id+token_hash+user_id) on the UPDATE itself and
	// verify exactly one row changed. A missing or changed row means the
	// session was revoked/replaced between revalidation and now; roll back any
	// consumed factor and refuse sudo rather than silently succeeding.
	res, err := tx.ExecContext(r.Context(), `UPDATE sessions SET sudo_until=? WHERE id=? AND token_hash=? AND user_id=?`, fmtTime(until), sess.ID, sess.TokenHash, sess.UserID)
	if err != nil {
		internalError(w)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		internalError(w)
		return
	}
	if n != 1 {
		authError(w, ErrSessionNotFound)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sudo_until": until})
}

// handleSetup begins enrollment: a fresh secret stored encrypted as pending,
// never touching the active credential until enable confirms it.
func (s *Service) handleSetup(w http.ResponseWriter, r *http.Request) {
	tx, sess, ok := s.sudoTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	var enabled bool
	if err := tx.QueryRowContext(r.Context(), `SELECT totp_enabled FROM users WHERE id=?`, sess.UserID).Scan(&enabled); err != nil {
		internalError(w)
		return
	}
	// Re-running setup replaces any abandoned pending secret; the active
	// secret is only ever replaced by disable followed by a new enrollment.
	if enabled {
		writeError(w, 409, "mfa_enabled", "MFA is already enabled.")
		return
	}
	sec, err := totp.GenerateSecret()
	if err != nil {
		internalError(w)
		return
	}
	enc, err := s.box.Seal(sec)
	if err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET totp_pending_secret_enc=?,updated_at=? WHERE id=?`, enc, fmtTime(s.now.Now()), sess.UserID); err != nil {
		internalError(w)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, map[string]any{
		"secret":      sec,
		"otpauth_url": totp.OTPAuthURL("AxionPanel", sess.User.Username, sec, totp.Default),
	})
}

// handleEnable confirms enrollment, publishes the hashed recovery codes once,
// and revokes every other session because the account's security changed.
func (s *Service) handleEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Code) > 8 {
		writeError(w, 400, "invalid_request", "Invalid code.")
		return
	}
	tx, sess, ok := s.sudoTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	var pending sql.NullString
	var enabled bool
	if err := tx.QueryRowContext(r.Context(), `SELECT totp_pending_secret_enc,totp_enabled FROM users WHERE id=?`, sess.UserID).Scan(&pending, &enabled); err != nil {
		internalError(w)
		return
	}
	if enabled || !pending.Valid {
		writeError(w, 409, "no_pending_mfa", "No pending MFA enrollment.")
		return
	}
	sec, err := s.box.Open(pending.String)
	if err != nil {
		authError(w, errUnavailable)
		return
	}
	step, matched := totp.Match(sec, req.Code, s.now.Now(), totp.Default, 1)
	if !matched {
		// Enrollment guesses share the per-user MFA failure budget.
		if err := s.recordMFAFailure(r.Context(), tx, s.clientIP(r), sess.UserID); err != nil || tx.Commit() != nil {
			internalError(w)
			return
		}
		writeError(w, 422, "invalid_mfa_code", "Code is not valid.")
		return
	}
	codes, err := s.makeRecoveryCodes(r.Context(), tx, sess.UserID)
	if err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET totp_secret_enc=totp_pending_secret_enc,totp_pending_secret_enc=NULL,totp_enabled=1,totp_last_step=?,updated_at=? WHERE id=?`, step, fmtTime(s.now.Now()), sess.UserID); err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id=? AND id<>?`, sess.UserID, sess.ID); err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM mfa_challenges WHERE user_id=?`, sess.UserID); err != nil {
		internalError(w)
		return
	}
	// The enrolling session proved the new factor just now.
	if _, err := tx.ExecContext(r.Context(), `UPDATE sessions SET mfa_passed=1 WHERE id=?`, sess.ID); err != nil {
		internalError(w)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
}

// makeRecoveryCodes issues 10 codes of 128 bits each, shown once and stored
// only as SHA-256 hashes.
func (s *Service) makeRecoveryCodes(ctx context.Context, tx *sql.Tx, userID int64) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id=?`, userID); err != nil {
		return nil, err
	}
	buf := make([]byte, 16)
	codes := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw := hex.EncodeToString(buf)
		code := raw[:8] + "-" + raw[8:]
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_recovery_codes(user_id,code_hash) VALUES(?,?)`, userID, hashToken(raw)); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// handleDisable tears down every MFA artifact in one transaction and revokes
// all other sessions. Requires sudo.
func (s *Service) handleDisable(w http.ResponseWriter, r *http.Request) {
	tx, sess, ok := s.sudoTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET totp_enabled=0,totp_secret_enc=NULL,totp_pending_secret_enc=NULL,totp_last_step=NULL,updated_at=? WHERE id=?`, fmtTime(s.now.Now()), sess.UserID); err != nil {
		internalError(w)
		return
	}
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM user_recovery_codes WHERE user_id=?`, []any{sess.UserID}},
		{`DELETE FROM mfa_challenges WHERE user_id=?`, []any{sess.UserID}},
		{`DELETE FROM auth_throttle WHERE scope='mfa_user' AND key=?`, []any{mfaKey(sess.UserID)}},
		{`DELETE FROM sessions WHERE user_id=? AND id<>?`, []any{sess.UserID, sess.ID}},
	} {
		if _, err := tx.ExecContext(r.Context(), q.query, q.args...); err != nil {
			internalError(w)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	s.clearCookie(w, MFACookie)
	writeJSON(w, 200, map[string]any{"ok": true})
}
