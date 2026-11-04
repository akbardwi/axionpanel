// Package webui serves the panel's built static frontend without a dev server.
package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// ClientRoutes are the vue-router paths that serve the app shell. The router
// uses HTML5 history (real paths, no "#"), so a refresh or a pasted link on
// one of these must return index.html. Anything else stays a 404 so typos and
// API mistakes are not masked. Keep in sync with web/src/router.js (a test
// enforces this).
var ClientRoutes = []string{
	"/overview", "/websites", "/databases", "/ssl", "/files", "/cron",
	"/containers", "/security", "/terminal", "/nodes", "/login", "/settings",
}

func isClientRoute(p string) bool {
	for _, route := range ClientRoutes {
		if p == route {
			return true
		}
	}
	return false
}

// Handler serves only files from the supplied build, plus the app shell for
// known client routes. Directory listings and unknown paths stay unavailable.
// If no build exists, the root and client routes report an actionable 503.
func Handler(build fs.FS) http.Handler {
	files := http.FileServer(http.FS(build))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		shell := r.URL.Path == "/" || isClientRoute(r.URL.Path)
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if shell {
			name = "index.html"
		}
		info, err := fs.Stat(build, name)
		if err != nil || info.IsDir() || strings.HasPrefix(name, ".") {
			if shell {
				http.Error(w, "UI build missing; run make web and rebuild the panel.", http.StatusServiceUnavailable)
			} else {
				http.NotFound(w, r)
			}
			return
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if shell {
			// FileServer would redirect "/index.html" to "/"; serve the shell
			// content directly so the client URL is preserved.
			http.ServeFileFS(w, r, build, "index.html")
			return
		}
		files.ServeHTTP(w, r)
	})
}

// SecurityHeaders applies to both API and frontend. Vue's compiled templates
// need no inline scripts. Existing token styling uses inline style attributes;
// only style-src permits them. HSTS is omitted until trusted TLS is configured.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
