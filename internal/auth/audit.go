package auth

import (
	"context"
	"errors"
	"net"

	"axionpanel/internal/audit"
)

// securityEvent accepts only typed, fixed audit fields. Actor names come from
// auth state, never headers; unknown login candidates remain explicitly
// unverified with a NULL foreign key.
func (s *Service) securityEvent(ctx context.Context, q audit.Execer, action audit.Action, outcome audit.Outcome, u *User, candidate, ip string, method audit.Method) error {
	e := audit.Event{Action: action, Outcome: outcome, Method: method}
	if net.ParseIP(ip) != nil {
		e.IP = ip
	}
	if u != nil {
		e.Actor = audit.Actor{ID: u.ID, Username: u.Username}
	} else {
		e.Candidate = candidate
	}
	return audit.New(s.now).Append(ctx, q, e)
}

func (s *Service) passwordRejection(ctx context.Context, username, ip string, verdict error) error {
	if !errors.Is(verdict, ErrInvalidCredentials) && !errors.Is(verdict, ErrLockedOut) && !errors.Is(verdict, ErrRateLimited) {
		return verdict
	}
	action := audit.Login
	var u *User
	if sess := sessionFrom(ctx); sess != nil {
		action = audit.Reauth
		u = &sess.User
	}
	outcome := audit.Failure
	if errors.Is(verdict, ErrLockedOut) || errors.Is(verdict, ErrRateLimited) {
		outcome = audit.Denied
	}
	if err := s.securityEvent(ctx, s.db, action, outcome, u, username, ip, audit.Password); err != nil {
		return err
	}
	return verdict
}
