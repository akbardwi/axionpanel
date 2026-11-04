package systemapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axionpanel/internal/agent"
	"axionpanel/internal/agentclient"
)

type fakeClient struct {
	info    *agentclient.Info
	stats   *agentclient.Stats
	metrics *agentclient.Metrics
	err     error
	calls   int
	lastCtx context.Context
}

func (f *fakeClient) Info(ctx context.Context) (*agentclient.Info, error) {
	f.calls++
	f.lastCtx = ctx
	return f.info, f.err
}

func (f *fakeClient) Stats(ctx context.Context) (*agentclient.Stats, error) {
	f.calls++
	f.lastCtx = ctx
	return f.stats, f.err
}

func (f *fakeClient) Metrics(ctx context.Context) (*agentclient.Metrics, error) {
	f.calls++
	f.lastCtx = ctx
	return f.metrics, f.err
}

func newMux(t *testing.T, c Client) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	(&Handler{Client: c}).Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Test-Auth") != "1" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": map[string]string{"code": "unauthorized", "message": "Sign in required."},
				})
				return
			}
			next.ServeHTTP(w, r.WithContext(agentclient.WithActor(r.Context(), 42)))
		})
	})
	return mux
}

func get(t *testing.T, mux *http.ServeMux, path string, header map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
	}
	return rec, body
}

var authed = map[string]string{"X-Test-Auth": "1"}

func TestRoutesRequireAuth(t *testing.T) {
	c := &fakeClient{info: &agentclient.Info{Hostname: "node-01"}}
	mux := newMux(t, c)
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/metrics", "/api/v1/system/agent"} {
		rec, _ := get(t, mux, path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth = %d, want 401", path, rec.Code)
		}
	}
	if c.calls != 0 {
		t.Fatalf("agent called %d times without auth", c.calls)
	}
}

func TestInfoReturnsAgentDocument(t *testing.T) {
	c := &fakeClient{info: &agentclient.Info{Version: "0.1.0-dev", Protocol: 1, Hostname: "node-01", CapabilityRevision: "rev1"}}
	rec, body := get(t, newMux(t, c), "/api/v1/system/info", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if body["hostname"] != "node-01" || body["capability_revision"] != "rev1" {
		t.Fatalf("body = %v", body)
	}
	if body["connected"] != true {
		t.Fatalf("connected flag missing: %v", body)
	}
}

func TestStatsReturnsMetrics(t *testing.T) {
	c := &fakeClient{stats: &agentclient.Stats{Load1: 0.25, MemTotalBytes: 1024, UptimeSeconds: 60}}
	rec, body := get(t, newMux(t, c), "/api/v1/system/stats", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if body["load1"] != 0.25 || body["mem_total_bytes"] != float64(1024) {
		t.Fatalf("body = %v", body)
	}
}

func TestUnavailableAgentIs503(t *testing.T) {
	c := &fakeClient{err: fmt.Errorf("%w: dial unix: no such file", agentclient.ErrUnavailable)}
	rec, body := get(t, newMux(t, c), "/api/v1/system/info", authed)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "agent_unavailable" {
		t.Fatalf("body = %v", body)
	}
	if strings.Contains(rec.Body.String(), "/run/") || strings.Contains(rec.Body.String(), "dial unix") {
		t.Fatalf("error leaks transport detail: %s", rec.Body.String())
	}
}

func TestAgentErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		code      string
		want      int
		wantCode  string
		wantNoMsg bool
	}{
		{"invalid params", 400, "invalid_params", 400, "invalid_params", false},
		{"unknown op", 404, "not_found", 404, "not_found", false},
		{"capability", 501, "capability_unavailable", 501, "capability_unavailable", false},
		{"forbidden", 403, "forbidden_by_policy", 403, "forbidden_by_policy", false},
		{"method not allowed", 405, "method_not_allowed", 405, "method_not_allowed", false},
		{"payload too large", 413, "payload_too_large", 413, "payload_too_large", false},
		{"unprocessable entity", 422, "config_test_failed", 422, "config_test_failed", false},
		{"too many requests", 429, "rate_limited", 429, "rate_limited", false},
		{"agent internal", 500, "internal", 502, "agent_error", true},
		{"bad gateway status", 502, "internal", 502, "agent_error", true},
		{"service unavailable", 503, "internal", 502, "agent_error", true},
		{"gateway timeout", 504, "internal", 502, "agent_error", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeClient{err: &agentclient.Error{Code: tc.code, Message: "agent said no", Status: tc.status}}
			rec, body := get(t, newMux(t, c), "/api/v1/system/stats", authed)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			errObj, _ := body["error"].(map[string]any)
			if errObj["code"] != tc.wantCode {
				t.Fatalf("code = %v, want %s", errObj["code"], tc.wantCode)
			}
			wantMessage := "agent said no" // Already sanitized by agentclient.
			if tc.wantNoMsg {
				wantMessage = "The agent could not complete the request."
			}
			if errObj["message"] != wantMessage {
				t.Fatalf("message = %v, want %q", errObj["message"], wantMessage)
			}
		})
	}
}

func TestStatusReportsDisconnectedWithoutFailing(t *testing.T) {
	c := &fakeClient{err: fmt.Errorf("%w: refused", agentclient.ErrUnavailable)}
	rec, body := get(t, newMux(t, c), "/api/v1/system/agent", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if body["connected"] != false || body["reason"] != "agent_unavailable" {
		t.Fatalf("body = %v", body)
	}
}

func TestStatusReportsConnected(t *testing.T) {
	c := &fakeClient{info: &agentclient.Info{Version: "0.1.0-dev", Protocol: 1, CapabilityRevision: "rev"}}
	rec, body := get(t, newMux(t, c), "/api/v1/system/agent", authed)
	if rec.Code != http.StatusOK || body["connected"] != true || body["version"] != "0.1.0-dev" {
		t.Fatalf("status = %d body=%v", rec.Code, body)
	}
}

func TestWrongMethodIs405(t *testing.T) {
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/metrics", "/api/v1/system/agent"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			c := &fakeClient{}
			req := httptest.NewRequest(method, path, strings.NewReader("{}"))
			req.Header.Set("X-Test-Auth", "1")
			rec := httptest.NewRecorder()
			newMux(t, c).ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("%s %s = %d Allow=%q, want 405 GET, HEAD", method, path, rec.Code, rec.Header().Get("Allow"))
			}
			if c.calls != 0 {
				t.Fatalf("%s %s reached the agent", method, path)
			}
		}
	}
}

func TestWrongMethodStillRequiresAuth(t *testing.T) {
	c := &fakeClient{}
	rec := httptest.NewRecorder()
	newMux(t, c).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/system/metrics", nil))
	if rec.Code != http.StatusUnauthorized || c.calls != 0 {
		t.Fatalf("unauthenticated POST = %d calls=%d, want 401 and no agent call", rec.Code, c.calls)
	}
}

func TestMetricsReturnsContractDocument(t *testing.T) {
	c := &fakeClient{metrics: &agentclient.Metrics{
		CPU:           &agentclient.CPUMetrics{UsagePercent: 0, LogicalCPUs: 2},
		Disk:          &agentclient.DiskMetrics{Mount: "/", TotalBytes: 1000, UsedBytes: 600, AvailableBytes: 300},
		NetworkReason: "no_default_route",
		ObservedAt:    "2026-11-04T12:00:00Z",
	}}
	rec, _ := get(t, newMux(t, c), "/api/v1/system/metrics", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	want := `{"cpu":{"usage_percent":0,"logical_cpus":2},"cpu_reason":"","disk":{"mount":"/","total_bytes":1000,"used_bytes":600,"available_bytes":300},"disk_reason":"","network":null,"network_reason":"no_default_route","observed_at":"2026-11-04T12:00:00Z"}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("metrics must not be cached")
	}
	if c.lastCtx == nil {
		t.Fatal("request context not propagated")
	}
}

func TestMetricsAgentFailuresAreSanitized(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
		code string
	}{
		"unavailable": {fmt.Errorf("%w: dial unix /run/axion/agent.sock", agentclient.ErrUnavailable), 503, "agent_unavailable"},
		"malformed":   {fmt.Errorf("%w: invalid metrics cpu", agentclient.ErrInvalidResponse), 503, "agent_unavailable"},
		"protocol":    {agentclient.ErrProtocol, 503, "agent_unavailable"},
		"internal":    {&agentclient.Error{Code: "internal", Message: "open /proc/stat", Status: 500}, 502, "agent_error"},
		"not found":   {&agentclient.Error{Code: "not_found", Message: "operation is not in the agent catalog", Status: 404}, 404, "not_found"},
		"cancelled":   {fmt.Errorf("%w: context canceled", agentclient.ErrUnavailable), 503, "agent_unavailable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := get(t, newMux(t, &fakeClient{err: tc.err}), "/api/v1/system/metrics", authed)
			errObj, _ := body["error"].(map[string]any)
			if rec.Code != tc.want || errObj["code"] != tc.code {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "/proc") || strings.Contains(rec.Body.String(), "/run/") {
				t.Fatalf("leaks host detail: %s", rec.Body.String())
			}
		})
	}
}

// TestIntegrationWithRealAgent exercises the client and handler against a real
// agent server on a Unix socket, so envelope and header handling are verified
// end to end rather than against a stub.
func TestIntegrationWithRealAgent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	srv := &agent.Server{
		Registry:      agent.NewRegistry(),
		Socket:        sock,
		AllowedUID:    uint32(os.Geteuid()),
		AllowRootPeer: true,
		Logger:        func(string, ...any) {},
	}
	agent.RegisterBuiltins(srv.Registry)
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := srv.Listen(ctx)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	mux := newMux(t, agentclient.New(sock))
	rec, body := get(t, mux, "/api/v1/system/info", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	host, _ := body["hostname"].(string)
	if host == "" {
		t.Fatalf("body = %v", body)
	}
	if body["protocol"] != float64(1) {
		t.Fatalf("protocol = %v", body["protocol"])
	}

	rec, body = get(t, mux, "/api/v1/system/stats", authed)
	if rec.Code != http.StatusOK || body["uptime_seconds"] == nil {
		t.Fatalf("stats status = %d body=%v", rec.Code, body)
	}

	rec, body = get(t, mux, "/api/v1/system/metrics", authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d body=%s", rec.Code, rec.Body.String())
	}
	for _, key := range []string{"cpu", "cpu_reason", "disk", "disk_reason", "network", "network_reason", "observed_at"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("metrics missing %q: %v", key, body)
		}
	}
	if body["cpu"] == nil || body["disk"] == nil {
		t.Fatalf("real Linux host must report cpu and disk: %v", body)
	}
}
