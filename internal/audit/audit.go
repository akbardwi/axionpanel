// Package audit persists security events in a bounded, append-only form.
//
// Callers never supply details text: every action has a fixed shape and only
// typed, bounded fields are stored. Audit rows are written through Append, so
// a mutation and its event can share one database transaction.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Action is the closed set of security events the panel can record.
type Action string

const (
	Login          Action = "auth.login"
	SessionCreate  Action = "auth.session.create"
	PasswordVerify Action = "auth.password.verify"
	LoginMFA       Action = "auth.login.mfa"
	MFASetup       Action = "auth.mfa.setup"
	MFAChallenge   Action = "auth.mfa.challenge"
	Logout         Action = "auth.logout"
	Reauth         Action = "auth.reauth"
	PasswordChange Action = "auth.password.change"
	MFAEnable      Action = "auth.mfa.enable"
	MFADisable     Action = "auth.mfa.disable"
	RecoveryCode   Action = "auth.recovery_code.use"
	RecoveryCodes  Action = "auth.recovery_codes.generate"
)

// Outcome mirrors the audit_log CHECK constraint.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Method is a fixed authentication-factor label.
type Method string

const (
	Password Method = "password"
	TOTP     Method = "totp"
	Recovery Method = "recovery_code"
	Session  Method = "session"
)

// Actor is the verified identity from the authenticated session or the user
// row that was just authenticated. Candidate is only for an unverified login
// name and must never be treated as an actor.
type Actor struct {
	ID       int64
	Username string
}

// Event is the complete, typed audit input. There is deliberately no details,
// body, header or free-form error field.
type Event struct {
	Actor     Actor
	Action    Action
	Outcome   Outcome
	IP        string
	Candidate string
	Method    Method
	// TargetUser is set for account-security changes and must match Actor.
	TargetUser int64
}

type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Writer appends events. It is safe for concurrent use: it holds no state
// beyond the clock.
type Writer struct{ now Clock }

func New(clock Clock) *Writer {
	if clock == nil {
		clock = systemClock{}
	}
	return &Writer{now: clock}
}

// Execer is implemented by *sql.DB and *sql.Tx. Passing the transaction that
// performs the mutation makes the audit row atomic with it.
type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type details struct {
	CandidateUsername string `json:"candidate_username,omitempty"`
	CandidateVerified *bool  `json:"candidate_verified,omitempty"`
	Method            Method `json:"method,omitempty"`
}

// Append validates and persists one event. Invalid actions, outcomes,
// methods, addresses or actors are rejected rather than stored verbatim.
func (w *Writer) Append(ctx context.Context, q Execer, e Event) error {
	if q == nil {
		return errors.New("audit: nil executor")
	}
	if !validAction(e.Action) {
		return errors.New("audit: invalid action")
	}
	if e.Outcome != Success && e.Outcome != Failure && e.Outcome != Denied {
		return errors.New("audit: invalid outcome")
	}
	if e.Method != "" && e.Method != Password && e.Method != TOTP && e.Method != Recovery && e.Method != Session {
		return errors.New("audit: invalid method")
	}
	ip := ""
	if e.IP != "" {
		parsed := net.ParseIP(e.IP)
		if parsed == nil {
			return errors.New("audit: invalid ip")
		}
		ip = parsed.String()
	}
	if e.Actor.ID < 0 || (e.Actor.ID == 0 && e.Actor.Username != "") {
		return errors.New("audit: inconsistent actor")
	}
	if e.TargetUser != 0 && e.TargetUser != e.Actor.ID {
		return errors.New("audit: target must be the actor")
	}
	var actorID any
	var username any
	if e.Actor.ID > 0 {
		actorID = e.Actor.ID
		name, err := boundedText(e.Actor.Username, 128)
		if err != nil || name == "" {
			return errors.New("audit: invalid actor")
		}
		username = name
	}
	d := details{Method: e.Method}
	if e.Actor.ID == 0 && e.Candidate != "" {
		name, _ := boundedText(e.Candidate, 128)
		d.CandidateUsername = name
		verified := false
		d.CandidateVerified = &verified
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	var target any
	if targetType(e.Action) != nil {
		target = "user"
	}
	var targetID any
	if target != nil && e.Actor.ID > 0 {
		targetID = strconv.FormatInt(e.Actor.ID, 10)
	}
	res, err := q.ExecContext(ctx, `INSERT INTO audit_log(user_id,username,ip,action,target_type,target_id,details,outcome,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		actorID, username, ip, string(e.Action), target, targetID, string(encoded), string(e.Outcome),
		w.now.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: append result: %w", err)
	}
	if n != 1 {
		return errors.New("audit: append did not persist one row")
	}
	return nil
}

func validAction(a Action) bool {
	switch a {
	case Login, SessionCreate, PasswordVerify, LoginMFA, MFASetup, MFAChallenge, Logout, Reauth, PasswordChange, MFAEnable, MFADisable, RecoveryCode, RecoveryCodes:
		return true
	}
	return false
}

func targetType(a Action) any {
	switch a {
	case PasswordChange, MFAEnable, MFADisable, RecoveryCode, RecoveryCodes:
		return "user"
	}
	return nil
}

// boundedText makes attacker-influenced names safe for JSON and logs: invalid
// UTF-8 and control characters become spaces, then the value is cut on a
// rune boundary.
func boundedText(s string, max int) (string, error) {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, " ")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		s = s[:max]
		// Byte truncation may cut a rune; drop the dangling bytes.
		s = strings.ToValidUTF8(s, "")
		s = strings.TrimSpace(s)
	}
	return s, nil
}
