// Package webui serves the panel's built static frontend without a dev server.
package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Handler serves only files from the supplied build. Hash routing means no
// index fallback is necessary. Directory listings and unknown API paths stay
// unavailable. If no build exists, the root reports an actionable 503.
func Handler(build fs.FS) http.Handler {
	files := http.FileServer(http.FS(build))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		info, err := fs.Stat(build, name)
		if err != nil || info.IsDir() || strings.HasPrefix(name, ".") {
			if name == "index.html" && r.URL.Path == "/" {
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
