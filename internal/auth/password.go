package auth

import (
	"database/sql"
	"errors"
	"net/http"

	"axionpanel/internal/audit"
)

// handlePassword rotates the caller's password behind a fresh sudo grant
// (recent re-authentication, which for MFA accounts also proves the second
// factor) and revokes all sessions, including the caller. The audit row
// commits atomically
// with the credential change and the session revocation.
func (s *Service) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.NewPassword) == 0 || len(req.NewPassword) > maxPassword {
		writeError(w, 400, "invalid_request", "Invalid new password length.")
		return
	}
	sess := sessionFrom(r.Context())
	if !s.requireSudo(w, sess) {
		return
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		internalError(w)
		return
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	// Revalidate identity and sudo under the write lock so a revoked or
	// replaced session cannot rotate the password it no longer owns.
	var (
		status   string
		enabled  bool
		passed   bool
		sudo     sql.NullString
		expires  string
		lastSeen string
	)
	err = tx.QueryRowContext(r.Context(), `SELECT u.status,u.totp_enabled,s.mfa_passed,s.sudo_until,s.expires_at,s.last_seen_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.token_hash=? AND s.user_id=?`, sess.ID, sess.TokenHash, sess.UserID).Scan(&status, &enabled, &passed, &sudo, &expires, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (status != "active" || (enabled && !passed))) {
		authError(w, ErrSessionNotFound)
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	until := parseNullTime(sudo)
	if until == nil || !s.now.Now().Before(*until) || !s.now.Now().Before(parseTime(expires)) || s.now.Now().Sub(parseTime(lastSeen)) >= s.cfg.SessionIdleTTL {
		authError(w, ErrSessionNotFound)
		return
	}
	now := s.now.Now()
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET password_hash=?,updated_at=? WHERE id=?`, hash, fmtTime(now), sess.UserID); err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM mfa_challenges WHERE user_id=?`, sess.UserID); err != nil {
		internalError(w)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id=?`, sess.UserID); err != nil {
		internalError(w)
		return
	}
	if err := s.securityEvent(r.Context(), tx, audit.PasswordChange, audit.Success, &sess.User, "", s.clientIP(r), audit.Password); err != nil {
		internalError(w)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w)
		return
	}
	s.clearCookie(w, SessionCookie)
	s.clearCookie(w, MFACookie)
	s.clearCookie(w, CSRFCookie)
	writeJSON(w, 200, map[string]any{"ok": true})
}
