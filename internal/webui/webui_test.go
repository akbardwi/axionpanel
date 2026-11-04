package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func builtFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>AxionPanel</title>")},
		"assets/index-abc.js":  {Data: []byte("console.log(1)")},
		"assets/index-abc.css": {Data: []byte("body{}")},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestServesIndexAtRoot(t *testing.T) {
	rec := get(t, Handler(builtFS()), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "AxionPanel") {
		t.Errorf("body = %q, want index.html", rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache so new builds load", cc)
	}
}

func TestServesHashedAssetsImmutable(t *testing.T) {
	rec := get(t, Handler(builtFS()), "/assets/index-abc.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("asset = %d, want 200", rec.Code)
	}
	if body, _ := io.ReadAll(rec.Body); string(body) != "console.log(1)" {
		t.Errorf("asset body = %q", body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("asset Cache-Control = %q, want immutable (content-hashed names)", cc)
	}
}

func TestClientRoutesServeIndexForHistoryRouting(t *testing.T) {
	// The router uses real paths (no hash), so a refresh or a pasted link on a
	// client route must serve the app shell and let vue-router resolve it.
	for _, p := range []string{"/overview", "/websites", "/containers", "/nodes", "/login"} {
		rec := get(t, Handler(builtFS()), p)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (SPA shell)", p, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "AxionPanel") {
			t.Errorf("GET %s body = %q, want index.html", p, rec.Body)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s Cache-Control = %q, want no-cache", p, cc)
		}
	}
}

func TestUnknownPathIs404NotIndex(t *testing.T) {
	// Only known client routes get the shell. Unknown paths must not return
	// index.html (which would mask typos and API mistakes).
	for _, p := range []string{"/nope", "/assets/missing.js", "/api/v1/unknown", "/overview/extra"} {
		if rec := get(t, Handler(builtFS()), p); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

func TestNoDirectoryListing(t *testing.T) {
	if rec := get(t, Handler(builtFS()), "/assets/"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /assets/ = %d, want 404 (no listing)", rec.Code)
	}
}

func TestMissingBuildIs503(t *testing.T) {
	for _, p := range []string{"/", "/overview"} {
		rec := get(t, Handler(fstest.MapFS{".gitkeep": {}}), p)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s without a build = %d, want 503", p, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "make web") {
			t.Errorf("GET %s body = %q, want build hint", p, rec.Body)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	rec := get(t, SecurityHeaders(inner), "/anything")
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, part := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP %q missing %q", csp, part)
		}
	}
	// Only script-src matters for script injection; style-src 'unsafe-inline'
	// is a deliberate tradeoff for the views' inline style attributes.
	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "script-src") && strings.Contains(directive, "unsafe") {
			t.Errorf("CSP %q must not allow unsafe scripts", directive)
		}
	}
}
