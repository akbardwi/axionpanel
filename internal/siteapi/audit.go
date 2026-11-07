package siteapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// The shared audit.Writer has a closed auth-only action set. Keep the static
// site action shape private and fixed rather than extending it outside this
// package's ownership. These rows use the same append-only audit_log table.
type AuditEvent struct {
	ActorID                                         int64
	Username, Action, Outcome, Target, TargetID, IP string
	Details                                         map[string]any
}

func appendAudit(ctx context.Context, tx *sql.Tx, e *AuditEvent) error {
	if e.ActorID <= 0 || !ValidOperationID(e.TargetID) || e.Target != targetType || (e.Action != "site.create" && e.Action != "site.remove") || e.Outcome != "success" {
		return errors.New("invalid static audit event")
	}
	b, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO audit_log(user_id,username,ip,action,target_type,target_id,details,outcome,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, e.ActorID, e.Username, e.IP, e.Action, e.Target, e.TargetID, string(b), e.Outcome, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("audit intent missing")
	}
	return nil
}
