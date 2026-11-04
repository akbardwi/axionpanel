package audit_test

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"axionpanel/internal/audit"
	"github.com/pressly/goose/v3"
)

func TestWriterRejectsIgnoredInsert(t *testing.T) {
	db := database(t)
	if _, err := db.Exec(`CREATE TRIGGER ignore_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if err := audit.New(clock{}).Append(context.Background(), db, audit.Event{Action: audit.Login, Outcome: audit.Success}); err == nil {
		t.Fatal("ignored insert falsely reported durable")
	}
}
func TestAccountTargetIsTypedActor(t *testing.T) {
	db := database(t)
	db.Exec(`INSERT INTO users(id,username,password_hash) VALUES(1,'admin','unused')`)
	w := audit.New(clock{})
	if err := w.Append(context.Background(), db, audit.Event{Actor: audit.Actor{ID: 1, Username: "admin"}, Action: audit.PasswordChange, Outcome: audit.Success, TargetUser: 1}); err != nil {
		t.Fatal(err)
	}
	var typ, id string
	if err := db.QueryRow(`SELECT target_type,target_id FROM audit_log`).Scan(&typ, &id); err != nil || typ != "user" || id != "1" {
		t.Fatalf("target %q %q %v", typ, id, err)
	}
	if err := w.Append(context.Background(), db, audit.Event{Actor: audit.Actor{ID: 1, Username: "admin"}, Action: audit.PasswordChange, Outcome: audit.Success, TargetUser: 2}); err == nil {
		t.Fatal("arbitrary target accepted")
	}
}
func TestAppendAutoIDAfterExplicitID(t *testing.T) {
	db := database(t)
	if _, err := db.Exec(`INSERT INTO audit_log(id,action,outcome) VALUES(7,'first','success')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log(action,outcome) VALUES('second','success')`); err != nil {
		t.Fatalf("auto-ID append rejected: %v", err)
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM audit_log WHERE action='second'`).Scan(&id); err != nil || id != 8 {
		t.Fatalf("auto id=%d err=%v", id, err)
	}
}

// An unspecified NEW.rowid in a BEFORE INSERT trigger is undefined; it must
// never collide with the valid explicit -1 ID and block automatic allocation.
func TestWriterAutoIDAfterNegativeOne(t *testing.T) {
	for _, positiveMax := range []bool{false, true} {
		name := "negative_only"
		if positiveMax {
			name = "positive_max"
		}
		t.Run(name, func(t *testing.T) {
			db := database(t)
			ctx := context.Background()
			for _, id := range []int64{-2, -1} {
				if _, err := db.Exec(`INSERT INTO audit_log(id,action,outcome) VALUES(?,'original','success')`, id); err != nil {
					t.Fatal(err)
				}
			}
			want := int64(0)
			if positiveMax {
				if _, err := db.Exec(`INSERT INTO audit_log(id,action,outcome) VALUES(42,'original','success')`); err != nil {
					t.Fatal(err)
				}
				want = 43
			}
			w := audit.New(clock{})
			for i := int64(0); i < 2; i++ {
				if err := w.Append(ctx, db, audit.Event{Action: audit.Login, Outcome: audit.Success}); err != nil {
					t.Fatalf("Writer.Append after explicit -1 (positiveMax=%v): %v", positiveMax, err)
				}
			}
			var first, last int64
			var n int
			if err := db.QueryRow(`SELECT min(id),max(id),count(*) FROM audit_log WHERE action='auth.login'`).Scan(&first, &last, &n); err != nil || first != want || last != want+1 || n != 2 {
				t.Fatalf("auto IDs: first=%d last=%d count=%d want=%d,%d err=%v", first, last, n, want, want+1, err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE id IN (-2,-1) AND action='original'`).Scan(&n); err != nil || n != 2 {
				t.Fatalf("negative history changed: count=%d err=%v", n, err)
			}
		})
	}
}

func TestAppendOnlyMigrationDownUp(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	var migrations fs.FS = os.DirFS("../store/migrations")
	p, err := goose.NewProvider(goose.DialectSQLite3, db, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Down(ctx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err = db.Exec(`INSERT INTO audit_log(action,outcome) VALUES('test','success'); DELETE FROM audit_log`); err != nil {
		t.Fatalf("down guard remained: %v", err)
	}
	if _, err = db.Exec(`INSERT INTO audit_log(id,action,outcome) VALUES(1,'test','success')`); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"REPLACE", "INSERT OR REPLACE"} {
		if _, err = db.Exec(prefix + ` INTO audit_log(id,action,outcome) VALUES(1,'test','failure')`); err != nil {
			t.Fatalf("down left replacement guard for %s: %v", prefix, err)
		}
	}
	if _, err = db.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}
	if _, err = db.Exec(`INSERT INTO audit_log(action,outcome) VALUES('test','success')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM audit_log`); err == nil {
		t.Fatal("up did not restore delete guard")
	}
	var id int64
	if err = db.QueryRow(`SELECT id FROM audit_log`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"REPLACE", "INSERT OR REPLACE"} {
		if _, err = db.Exec(prefix+` INTO audit_log(id,action,outcome) VALUES(?,'forged','failure')`, id); err == nil {
			t.Fatalf("up did not restore replacement guard for %s", prefix)
		}
	}
	var action string
	if err = db.QueryRow(`SELECT action FROM audit_log WHERE id=?`, id).Scan(&action); err != nil || action != "test" {
		t.Fatalf("up replacement changed history: %q err=%v", action, err)
	}
}
