package siteapi

import (
	"axionpanel/internal/agentclient"
	"axionpanel/internal/auth"
	"axionpanel/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type testAgent struct {
	mu       sync.Mutex
	calls    []string
	mutation func(string, OperationParams) error
	fail     error
}

func (a *testAgent) Call(ctx context.Context, op string, params any, out any) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("agent call missing deadline")
	}
	a.mu.Lock()
	a.calls = append(a.calls, op)
	a.mu.Unlock()
	b, _ := json.Marshal(params)
	var p OperationParams
	json.Unmarshal(b, &p)
	if op == "site.plan" {
		if a.fail != nil {
			return a.fail
		}
		b, _ = json.Marshal(Plan{Domain: p.Domain, Root: "/srv/static/" + p.Domain + "/public", Listen: "127.0.0.1:8888"})
	} else {
		if a.mutation != nil {
			if err := a.mutation(op, p); err != nil {
				return err
			}
		}
		status := "applied"
		if op == "site.remove" {
			status = "removed"
		}
		b, _ = json.Marshal(map[string]any{"domain": p.Domain, "operation_id": p.OperationID, "status": status, "changed": true})
	}
	return json.Unmarshal(b, out)
}

type env struct {
	db    *sql.DB
	svc   *auth.Service
	sess  *auth.Session
	mux   *http.ServeMux
	agent *testAgent
}

func setup(t *testing.T, a *testAgent) *env {
	t.Helper()
	db := openDB(t)
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := auth.New(db, auth.DefaultConfig(), nil)
	u, err := svc.Create(context.Background(), "admin", "secret", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), u.ID, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `UPDATE sessions SET sudo_until=?`, time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
	h, err := New(db, a, svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return &env{db: db, svc: svc, sess: sess, mux: mux, agent: a}
}
func (e *env) req(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", auth.DefaultConfig().Origin)
	r.Header.Set("X-CSRF-Token", e.sess.CSRFToken)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: e.sess.Token})
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}
func count(t *testing.T, db *sql.DB, q string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestInventoryEmptyAndAgentUnavailable(t *testing.T) {
	e := setup(t, &testAgent{fail: agentclient.ErrUnavailable})
	w := e.req("GET", "/api/v1/sites", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"data":[]`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = e.req("GET", "/api/v1/sites/plan?domain=example.com", "")
	if w.Code != 503 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
func TestCreateDurableIntentDeleteRetainsDomain(t *testing.T) {
	a := &testAgent{}
	e := setup(t, a)
	a.mutation = func(op string, p OperationParams) error {
		if op == "site.status" {
			return nil
		}
		if !ValidOperationID(p.OperationID) {
			t.Errorf("bad ID %q", p.OperationID)
		}
		var n int
		if err := e.db.QueryRow(`SELECT count(*) FROM jobs j JOIN audit_log a ON a.target_id=j.id WHERE j.id=? AND j.status='running' AND j.user_id=? AND j.server_id=1`, p.OperationID, e.sess.UserID).Scan(&n); err != nil || n != 1 {
			t.Errorf("no durable intent: %d %v", n, err)
		}
		return nil
	}
	w := e.req("POST", "/api/v1/sites", `{"domain":"EXAMPLE.COM","kind":"static"}`)
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	var response struct {
		Site Site `json:"site"`
		Job  Job  `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Site.Status != "active" || response.Job.Status != "succeeded" || response.Site.SystemUserID != nil || response.Site.Root != "/srv/static/example.com/public" || response.Site.Listen != "127.0.0.1:8888" {
		t.Fatalf("%s", w.Body)
	}
	if count(t, e.db, `SELECT count(*) FROM system_users`) != 0 {
		t.Fatal("fictional OS user inserted")
	}
	w = e.req("GET", "/api/v1/jobs/"+response.Job.ID, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"succeeded"`) {
		t.Fatalf("job %d %s", w.Code, w.Body)
	}
	w = e.req("GET", "/api/v1/sites/1", "")
	if w.Code != 200 {
		t.Fatalf("get %d %s", w.Code, w.Body)
	}
	for _, body := range []string{`{"confirm_domain":"wrong.example"}`, `{"confirm_domain":"example.com","delete_files":true}`} {
		w = e.req("DELETE", "/api/v1/sites/1", body)
		if w.Code != 400 {
			t.Fatalf("unsafe delete %d %s", w.Code, w.Body)
		}
	}
	w = e.req("DELETE", "/api/v1/sites/1?delete_files=true", `{"confirm_domain":"example.com"}`)
	if w.Code != 400 {
		t.Fatalf("unsafe query %d %s", w.Code, w.Body)
	}
	w = e.req("DELETE", "/api/v1/sites/1", `{"confirm_domain":"example.com"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"retained_content":true`) {
		t.Fatalf("delete %d %s", w.Code, w.Body)
	}
	if count(t, e.db, `SELECT count(*) FROM sites WHERE status='deleted'`) != 1 || count(t, e.db, `SELECT count(*) FROM site_domains`) != 1 {
		t.Fatal("tombstone lost")
	}
	w = e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
	if w.Code != 409 {
		t.Fatalf("reuse %d %s", w.Code, w.Body)
	}
}
func TestValidationAndScope(t *testing.T) {
	e := setup(t, &testAgent{})
	for _, body := range []string{`{"domain":"*.example.com"}`, `{"domain":"127.0.0.1"}`, `{"domain":"münich.example"}`, `{"domain":"localhost"}`, `{"domain":"-bad.example"}`, `{"domain":"example.com","root":"/etc"}`, `{"domain":"example.com","kind":"php"}`, `{"domain":"example.com","server_id":2}`, `{"domain":"example.com"} {}`} {
		w := e.req("POST", "/api/v1/sites", body)
		if w.Code != 400 {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if count(t, e.db, `SELECT count(*) FROM sites`) != 0 {
		t.Fatal("invalid requests persisted")
	}
	for _, path := range []string{"/api/v1/sites?server_id=2", "/api/v1/sites/plan?domain=example.com&server_id=2"} {
		if w := e.req("GET", path, ""); w.Code != 400 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	w := e.req("GET", "/api/v1/jobs/00000000000000000000000000000000", "")
	if w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}
func TestAuditFailureStopsDispatch(t *testing.T) {
	for _, mode := range []string{"ABORT, 'offline'", "IGNORE"} {
		t.Run(mode, func(t *testing.T) {
			a := &testAgent{}
			e := setup(t, a)
			exec(t, e.db, `CREATE TRIGGER audit_fail BEFORE INSERT ON audit_log BEGIN SELECT RAISE(`+mode+`); END`)
			w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
			if w.Code != 500 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			for _, op := range a.calls {
				if op == "site.apply" {
					t.Fatal("dispatch despite failed audit")
				}
			}
			if count(t, e.db, `SELECT count(*) FROM sites`) != 0 || count(t, e.db, `SELECT count(*) FROM jobs`) != 0 {
				t.Fatal("intent not rolled back")
			}
		})
	}
}
func TestAmbiguousOutcomeAndInterruptedStartup(t *testing.T) {
	a := &testAgent{mutation: func(string, OperationParams) error { return errors.New("lost response with private details") }}
	e := setup(t, a)
	w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"manual_reconciliation"`) || strings.Contains(w.Body.String(), "private details") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if count(t, e.db, `SELECT count(*) FROM sites WHERE status='error'`) != 1 {
		t.Fatal("ambiguous site not error")
	}
	exec(t, e.db, `UPDATE jobs SET status='running',error=NULL,finished_at=NULL`)
	exec(t, e.db, `UPDATE sites SET status='provisioning'`)
	_, err := New(e.db, a, e.svc)
	if err != nil {
		t.Fatal(err)
	}
	if count(t, e.db, `SELECT count(*) FROM jobs WHERE status='failed' AND error='interrupted_manual_reconciliation'`) != 1 {
		t.Fatal("unfinished job not interrupted")
	}
	if count(t, e.db, `SELECT count(*) FROM sites WHERE status='error'`) != 1 {
		t.Fatal("unfinished site not error")
	}
}
func TestConcurrentDuplicateReservation(t *testing.T) {
	a := &testAgent{}
	e := setup(t, a)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`).Code }()
	}
	wg.Wait()
	close(codes)
	success, conflict := 0, 0
	for c := range codes {
		if c == 200 {
			success++
		}
		if c == 409 {
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	if count(t, e.db, `SELECT count(*) FROM sites`) != 1 {
		t.Fatal("duplicate sites")
	}
}

func TestGetRequiresSessionAndMutationRequiresCsrfSudo(t *testing.T) {
	e := setup(t, &testAgent{})
	r := httptest.NewRequest("GET", "/api/v1/sites", nil)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("anonymous list %d", w.Code)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		func(r *http.Request) { exec(t, e.db, `UPDATE sessions SET sudo_until=NULL`) },
	} {
		r = httptest.NewRequest("POST", "/api/v1/sites", strings.NewReader(`{"domain":"example.com"}`))
		r.Header.Set("Origin", auth.DefaultConfig().Origin)
		r.Header.Set("X-CSRF-Token", e.sess.CSRFToken)
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: e.sess.Token})
		mutate(r)
		w = httptest.NewRecorder()
		e.mux.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("mutation guard %d %s", w.Code, w.Body)
		}
		exec(t, e.db, `UPDATE sessions SET sudo_until=?`, time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
	}
	if count(t, e.db, `SELECT count(*) FROM sites`) != 0 {
		t.Fatal("guarded mutation persisted")
	}
}
