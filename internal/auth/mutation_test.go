package auth

import (
	"axionpanel/internal/store"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRequireMutationRealSession(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := New(db, DefaultConfig(), nil)
	u, err := svc.Create(context.Background(), "mutation-admin", "secret", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), u.ID, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if _, err = db.Exec(`UPDATE sessions SET sudo_until=? WHERE id=?`, until, sess.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, origin, csrf string
		cookie             bool
		setup              string
		want               int
	}{
		{"allowed", DefaultConfig().Origin, sess.CSRFToken, true, "", 204},
		{"origin", "https://evil.test", sess.CSRFToken, true, "", 403},
		{"no-session", DefaultConfig().Origin, sess.CSRFToken, false, "", 401},
		{"csrf", DefaultConfig().Origin, "bad", true, "", 403},
		{"stale", DefaultConfig().Origin, sess.CSRFToken, true, `UPDATE sessions SET sudo_until=NULL`, 403},
		{"non-admin", DefaultConfig().Origin, sess.CSRFToken, true, `UPDATE users SET role='user'`, 403},
		{"suspended", DefaultConfig().Origin, sess.CSRFToken, true, `UPDATE users SET status='suspended'`, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db.Exec(`UPDATE sessions SET sudo_until=?`, until)
			db.Exec(`UPDATE users SET role='admin',status='active'`)
			if tc.setup != "" {
				if _, err := db.Exec(tc.setup); err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest("POST", "/mutation", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-CSRF-Token", tc.csrf)
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.Token})
			}
			w := httptest.NewRecorder()
			svc.RequireMutation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tx, _, ok := svc.MutationTx(w, r)
				if !ok {
					return
				}
				defer tx.Rollback()
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				w.WriteHeader(204)
			})).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

func TestMutationTxRevalidatesPrivilege(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := New(db, DefaultConfig(), nil)
	u, err := svc.Create(context.Background(), "admin", "secret", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), u.ID, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`UPDATE sessions SET sudo_until=?`, time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.Token})
	r.Header.Set("Origin", DefaultConfig().Origin)
	r.Header.Set("X-CSRF-Token", sess.CSRFToken)
	w := httptest.NewRecorder()
	svc.RequireMutation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.Exec(`UPDATE users SET role='user'`); err != nil {
			t.Fatal(err)
		}
		tx, _, ok := svc.MutationTx(w, r)
		if ok {
			tx.Rollback()
			t.Fatal("revoked admin authorized transaction")
		}
	})).ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status=%d %s", w.Code, w.Body)
	}
}

func TestMutationTxRejectsExpiredSession(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := New(db, DefaultConfig(), nil)
	u, err := svc.Create(context.Background(), "admin", "secret", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), u.ID, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`UPDATE sessions SET sudo_until=?`, time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	db.Exec(`UPDATE sessions SET expires_at=?`, time.Now().Add(-time.Second).UTC().Format(time.RFC3339))
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.Token})
	r.Header.Set("Origin", DefaultConfig().Origin)
	r.Header.Set("X-CSRF-Token", sess.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess))
	w := httptest.NewRecorder()
	tx, _, ok := svc.MutationTx(w, r)
	if ok {
		tx.Rollback()
		t.Fatal("expired session authorized transaction")
	}
	if w.Code != 401 {
		t.Fatalf("status=%d %s", w.Code, w.Body)
	}
}
