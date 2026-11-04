package audit_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/audit"
	"axionpanel/internal/store"
)

type clock struct{}

func (clock) Now() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
func database(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestWriterBoundedTypedEvent(t *testing.T) {
	db := database(t)
	w := audit.New(clock{})
	ctx := context.Background()
	if err := w.Append(ctx, db, audit.Event{Action: audit.Login, Outcome: audit.Failure, IP: "192.0.2.1", Candidate: strings.Repeat("é", 200) + "\nforged", Method: audit.Password}); err != nil {
		t.Fatal(err)
	}
	var user sql.NullInt64
	var username sql.NullString
	var ip, action, details, outcome, created string
	if err := db.QueryRow(`SELECT user_id,username,ip,action,details,outcome,created_at FROM audit_log`).Scan(&user, &username, &ip, &action, &details, &outcome, &created); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(details), &d); err != nil {
		t.Fatal(err)
	}
	if user.Valid || username.Valid || ip != "192.0.2.1" || action != "auth.login" || outcome != "failure" || created != "2026-11-04T12:00:00Z" {
		t.Fatalf("unexpected event: %v %v %s %s %s %s", user, username, ip, action, outcome, created)
	}
	if len(d["candidate_username"].(string)) > 128 || d["candidate_verified"] != false || d["method"] != "password" || strings.ContainsAny(d["candidate_username"].(string), "\n\r") {
		t.Fatalf("unsafe details: %s", details)
	}
	for _, e := range []audit.Event{{Action: "arbitrary secret", Outcome: audit.Success}, {Action: audit.Login, Outcome: "secret"}, {Action: audit.Login, Outcome: audit.Success, Method: "secret"}, {Action: audit.Login, Outcome: audit.Success, IP: "not-an-ip"}} {
		if err := w.Append(ctx, db, e); err == nil {
			t.Fatalf("invalid event accepted: %+v", e)
		}
	}
}
func TestAuditTransactionAndAppendOnly(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	w := audit.New(clock{})
	if _, err := db.Exec(`INSERT INTO users(id,username,password_hash) VALUES(1,'admin','unused')`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Append(ctx, tx, audit.Event{Actor: audit.Actor{ID: 1, Username: "admin"}, Action: audit.Logout, Outcome: audit.Success}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&n)
	if n != 0 {
		t.Fatal("audit escaped transaction")
	}
	if err = w.Append(ctx, db, audit.Event{Actor: audit.Actor{ID: 1, Username: "admin"}, Action: audit.Logout, Outcome: audit.Success}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE audit_log SET details='{"forged":true}'`); err == nil {
		t.Fatal("audit update allowed")
	}
	if _, err = db.Exec(`DELETE FROM audit_log`); err == nil {
		t.Fatal("audit delete allowed")
	}
	if _, err = db.Exec(`DELETE FROM users WHERE id=1`); err != nil {
		t.Fatalf("user deletion must retain audit: %v", err)
	}
	var id sql.NullInt64
	var name string
	if err = db.QueryRow(`SELECT user_id,username FROM audit_log`).Scan(&id, &name); err != nil || id.Valid || name != "admin" {
		t.Fatalf("actor snapshot lost: %v %s %v", id, name, err)
	}
}
