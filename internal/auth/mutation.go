package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
)

// PanelHostname is the trusted startup-configured control-plane hostname.
func (s *Service) PanelHostname() string {
	u, err := url.Parse(s.cfg.Origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// RequireMutation gates every state-changing panel route. It is deliberately
// stricter than RequireAuth: the exact configured Origin, a valid session,
// the session CSRF token, fresh sudo re-authentication and an active admin
// account are all required. Route handlers must still call MutationTx so the
// privilege is revalidated inside the transaction that performs the write.
func (s *Service) RequireMutation(next http.Handler) http.Handler {
	return s.requireOrigin(s.requireAuth(s.requireCSRF(s.requireAdminSudo(next))))
}

func (s *Service) requireAdminSudo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		if sess == nil || sess.User.Role != "admin" || sess.User.Status != "active" {
			writeError(w, http.StatusForbidden, "forbidden", "Administrator access required.")
			return
		}
		if !s.requireSudo(w, sess) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MutationTx opens the write transaction for an authenticated mutation and
// revalidates, under SQLite's writer reservation, that the session still
// exists, its user is an active admin, MFA is satisfied and sudo has not
// expired. Callers must commit or roll back the returned transaction. The
// request-time middleware checks alone would leave a check-then-act window
// between authorization and the durable intent.
func (s *Service) MutationTx(w http.ResponseWriter, r *http.Request) (*sql.Tx, *Session, bool) {
	sess := sessionFrom(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
		return nil, nil, false
	}
	tx, err := s.writeTx(r.Context())
	if err != nil {
		internalError(w)
		return nil, nil, false
	}
	var status, role, expires, seen string
	var enabled, passed bool
	var sudo sql.NullString
	err = tx.QueryRowContext(r.Context(), `SELECT u.status,u.role,u.totp_enabled,s.mfa_passed,s.sudo_until,s.expires_at,s.last_seen_at
		FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.token_hash=?`,
		sess.ID, sess.TokenHash).Scan(&status, &role, &enabled, &passed, &sudo, &expires, &seen)
	now := s.now.Now()
	if err != nil || status != "active" || (enabled && !passed) || !now.Before(parseTime(expires)) || now.Sub(parseTime(seen)) >= s.cfg.SessionIdleTTL {
		tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			internalError(w)
		} else {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
		}
		return nil, nil, false
	}
	if role != "admin" {
		tx.Rollback()
		writeError(w, http.StatusForbidden, "forbidden", "Administrator access required.")
		return nil, nil, false
	}
	if until := parseNullTime(sudo); until == nil || !s.now.Now().Before(*until) {
		tx.Rollback()
		writeError(w, http.StatusForbidden, "sudo_required", "Recent password verification required.")
		return nil, nil, false
	}
	return tx, sess, true
}
