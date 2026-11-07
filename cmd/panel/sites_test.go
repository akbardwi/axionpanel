package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"axionpanel/internal/auth"
	"axionpanel/internal/store"
)

// The panel serves static-site mutations synchronously. The server write
// deadline must outlast the panel's dispatch budget (90s) plus the final
// durable bookkeeping, otherwise a slow but valid apply is cut mid-flight and
// the browser sees a transport error for a change that did happen.
func TestPanelWriteTimeoutOutlastsSiteDispatch(t *testing.T) {
	if panelWriteTimeout <= 95*time.Second {
		t.Fatalf("panelWriteTimeout=%s cannot cover a 90s site dispatch", panelWriteTimeout)
	}
}

func TestSiteRoutesMountUnderSessionAuth(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := auth.New(db, auth.DefaultConfig(), nil)
	user, err := svc.Create(context.Background(), "admin", "correct horse battery staple", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), user.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	agent := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		http.Error(w, `{"error":{"code":"unsupported","message":"not enabled"}}`, http.StatusNotImplemented)
	})}
	go func() { _ = agent.Serve(ln) }()
	defer agent.Close()

	mux := http.NewServeMux()
	if err := registerSiteRoutes(mux, db, svc, sock); err != nil {
		t.Fatalf("registerSiteRoutes: %v", err)
	}

	// Inventory is authenticated even when the agent cannot manage sites.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 0 {
		t.Fatalf("empty inventory rendered %d rows", len(body.Data))
	}

	// Mutations stay behind the mutation middleware, not a bare handler.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sites", nil))
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/v1/sites is not mounted: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sites?server_id=2", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("remote server list = %d, want 400", rec.Code)
	}
}
