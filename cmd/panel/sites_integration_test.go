package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/agent"
	"axionpanel/internal/auth"
	"axionpanel/internal/nginxsite"
	"axionpanel/internal/store"
)

// Acceptance test, not a replacement for each layer's test-first unit tests:
// real session -> panel routes -> Unix agent protocol/policy -> real isolated
// Nginx -> durable metadata. Nothing uses the host's service configuration.
func TestStaticSiteEndToEndOverUnixSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned adapter integration")
	}
	binary, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx unavailable")
	}
	base, err := os.MkdirTemp("/root/.hermes/cache/scratch", "sites-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	cfg := nginxsite.Config{StateDir: filepath.Join(base, "state"), ContentDir: filepath.Join(base, "content"), ConfigDir: filepath.Join(base, "conf"), Prefix: filepath.Join(base, "prefix"), NginxBinary: binary, NginxConfig: filepath.Join(base, "nginx.conf")}
	for _, d := range []string{cfg.StateDir, cfg.ContentDir, cfg.ConfigDir, cfg.Prefix} {
		if err = os.Mkdir(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chmod(cfg.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = probe.Addr().String()
	probe.Close()
	content := fmt.Sprintf("user root;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log %s/error.log;\nevents { worker_connections 64; }\nhttp { access_log off; client_body_temp_path %s/body; proxy_temp_path %s/proxy; fastcgi_temp_path %s/fastcgi; uwsgi_temp_path %s/uwsgi; scgi_temp_path %s/scgi; include %s/*.conf; }\n", cfg.Prefix, cfg.Prefix, cfg.Prefix, cfg.Prefix, cfg.Prefix, cfg.Prefix, cfg.Prefix, cfg.ConfigDir)
	if err = os.WriteFile(cfg.NginxConfig, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	nginxCmd := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, binary, append([]string{"-p", cfg.Prefix, "-c", cfg.NginxConfig, "-e", "stderr"}, args...)...).CombinedOutput()
		if e != nil {
			return fmt.Errorf("isolated nginx: %w: %s", e, out)
		}
		return nil
	}
	if err = nginxCmd(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := nginxCmd("-s", "quit"); e != nil {
			t.Error(e)
		}
	})
	manager, err := nginxsite.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	reg := agent.NewRegistry()
	agent.RegisterBuiltins(reg)
	agent.RegisterStaticSites(reg, manager)
	// Root-peer permission is limited to this in-process test harness. The actual
	// agent CLI refuses a root panel peer.
	rpc := &agent.Server{Registry: reg, Policy: agent.Policy{AllowStaticSites: true}, AllowedUID: 0, AllowRootPeer: true, StaticSitesTimeout: 100 * time.Second}
	sock := filepath.Join(base, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(7 * time.Second):
			t.Error("agent did not stop")
		}
	})
	db, err := store.Open(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	svc := auth.New(db, auth.DefaultConfig(), nil)
	user, err := svc.Create(context.Background(), "admin", "isolated-test-password-only", "admin")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.CreateSession(context.Background(), user.ID, "127.0.0.1", "integration")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET sudo_until=? WHERE id=?`, time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339), sess.ID); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err = registerSiteRoutes(mux, db, svc, sock); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", auth.DefaultConfig().Origin)
		r.Header.Set("X-CSRF-Token", sess.CSRFToken)
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess.Token})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	plan := request("GET", "/api/v1/sites/plan?domain=integration.example", "")
	if plan.Code != 200 {
		t.Fatalf("plan %d %s", plan.Code, plan.Body)
	}
	created := request("POST", "/api/v1/sites", `{"domain":"integration.example"}`)
	var result struct {
		Site struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
			Root   string `json:"root"`
		} `json:"site"`
		Job struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"job"`
		Retained bool `json:"retained_content"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if created.Code != 200 || result.Site.Status != "active" || result.Job.Status != "succeeded" {
		t.Fatalf("create %d %s", created.Code, created.Body)
	}
	job := request("GET", "/api/v1/jobs/"+result.Job.ID, "")
	if job.Code != 200 || !strings.Contains(job.Body.String(), `"succeeded"`) {
		t.Fatalf("job %d %s", job.Code, job.Body)
	}
	var intent int
	if err = db.QueryRow(`SELECT count(*) FROM audit_log WHERE action='site.create' AND target_id=?`, result.Job.ID).Scan(&intent); err != nil || intent != 1 {
		t.Fatalf("durable audit=%d err=%v", intent, err)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	served := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://"+cfg.Listen+"/", nil)
		req.Host = "integration.example"
		res, e := client.Do(req)
		if e == nil {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode == 200 && strings.Contains(string(body), "integration.example") {
				served = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !served {
		t.Fatal("site not serving after applied job")
	}
	if w := request("POST", "/api/v1/sites", `{"domain":"integration.example"}`); w.Code != 409 {
		t.Fatalf("duplicate=%d", w.Code)
	}
	if w := request("DELETE", fmt.Sprintf("/api/v1/sites/%d", result.Site.ID), `{"confirm_domain":"wrong.example"}`); w.Code != 400 {
		t.Fatalf("confirmation=%d", w.Code)
	}
	siteID := result.Site.ID
	root := result.Site.Root
	removed := request("DELETE", fmt.Sprintf("/api/v1/sites/%d", siteID), `{"confirm_domain":"integration.example"}`)
	if err = json.Unmarshal(removed.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if removed.Code != 200 || result.Site.Status != "deleted" || result.Job.Status != "succeeded" || !result.Retained {
		t.Fatalf("remove %d %s", removed.Code, removed.Body)
	}
	if _, err = os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Fatalf("content lost: %v", err)
	}
	if _, err = os.Stat(filepath.Join(cfg.ConfigDir, "integration.example.conf")); !os.IsNotExist(err) {
		t.Fatalf("vhost not removed: %v", err)
	}
	list := request("GET", "/api/v1/sites", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"data":[]`) {
		t.Fatalf("list %d %s", list.Code, list.Body)
	}
	if w := request("POST", "/api/v1/sites", `{"domain":"integration.example"}`); w.Code != 409 {
		t.Fatalf("tombstone reuse=%d", w.Code)
	}
	t.Log("real session -> panel -> Unix agent -> isolated Nginx -> retained removal passed")
}
