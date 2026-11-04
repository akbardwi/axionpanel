package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"axionpanel/internal/auth"
	"axionpanel/internal/store"
)

func TestSystemRoutesRequireSessionAndAttributeActor(t *testing.T) {
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
	actors := make(chan string, 10)
	agent := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actors <- r.Header.Get("Axion-Actor")
		w.Header().Set("Axion-Protocol", "1")
		if r.URL.Path == "/v1/info" {
			io.WriteString(w, `{"protocol":1,"version":"test","hostname":"node-01","os":"Ubuntu 26.04","arch":"arm64","kernel":"7.0.0","detected_tools":{},"capabilities":{},"capability_revision":"test-revision","operations":["system.stats"],"observed_at":"2026-11-03T10:00:00Z"}`)
			return
		}
		if r.URL.Path == "/v1/ops/system.metrics" {
			io.WriteString(w, `{"result":{"cpu":{"usage_percent":12.5,"logical_cpus":2},"cpu_reason":"","disk":{"mount":"/","total_bytes":1000,"used_bytes":600,"available_bytes":300},"disk_reason":"","network":null,"network_reason":"no_default_route","observed_at":"2026-11-03T10:00:00Z"}}`)
			return
		}
		io.WriteString(w, `{"result":{"load1":0.5,"load5":0.4,"load15":0.3,"mem_total_bytes":1024,"mem_available_bytes":512,"uptime_seconds":60,"observed_at":"2026-11-03T10:00:00Z"}}`)
	})}
	go func() { _ = agent.Serve(ln) }()
	defer agent.Close()
	mux := http.NewServeMux()
	registerSystemRoutes(mux, svc, sock)
	// Same broad API fallback as production must not hide method errors.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/metrics", "/api/v1/system/agent"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s wrong method = %d Allow=%q, want 405 GET, HEAD", path, rec.Code, rec.Header().Get("Allow"))
		}
	}
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/metrics", "/api/v1/system/agent"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 401 {
			t.Fatalf("%s unauth=%d", path, rec.Code)
		}
	}
	if len(actors) != 0 {
		t.Fatal("agent called before login")
	}
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/metrics", "/api/v1/system/agent"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
		req.Header.Set("Axion-Actor", "9999") // browser input must not select the audit actor
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s=%d %s", path, rec.Code, rec.Body.String())
		}
		if got := <-actors; got != strconv.FormatInt(user.ID, 10) {
			t.Fatalf("actor=%q, want authenticated user %d", got, user.ID)
		}
		var body map[string]any
		if err = json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("host data must not be cached")
		}
	}
	// Revoked sessions must not reach the agent.
	if err = svc.DeleteSession(context.Background(), sess.TokenHash); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/v1/system/info", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 || len(actors) != 0 {
		t.Fatalf("revoked=%d calls=%d", rec.Code, len(actors))
	}
}
