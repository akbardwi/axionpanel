// Command panel runs the AxionPanel API server and web UI.
// It runs unprivileged and delegates system operations to the agent.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"axionpanel/internal/auth"
	"axionpanel/internal/secret"
	"axionpanel/internal/store"
	"axionpanel/internal/webui"
	"axionpanel/web"
)

var version = "0.0.0-dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7800", "listen address")
	dbPath := flag.String("db", "panel.db", "SQLite metadata database path")
	keyPath := flag.String("secret-key", "", "secret key file for encrypted fields (default: secret.key next to -db)")
	origin := flag.String("origin", auth.DefaultConfig().Origin, "exact browser origin (scheme://host[:port]) allowed to call the API")
	insecureLoopback := flag.Bool("insecure-loopback", false, "allow a plain-HTTP loopback -origin for local development (cookies lose Secure)")
	bootstrap := flag.String("bootstrap-admin", "", "create the first admin user with this username, print a generated password, and exit")
	flag.Parse()

	cfg := auth.DefaultConfig()
	cfg.Origin = *origin
	cfg.AllowInsecureLoopback = *insecureLoopback
	if err := cfg.Validate(); err != nil {
		log.Fatalf("panel: -origin %q: %v (HTTP origins need a loopback host and -insecure-loopback)", *origin, err)
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(filepath.Dir(*dbPath), "secret.key")
	}
	box, err := secret.LoadOrCreate(*keyPath)
	if err != nil {
		log.Fatalf("panel: secret key: %v", err)
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("panel: %v", err)
	}
	defer db.Close()
	if err := store.Migrate(context.Background(), db); err != nil {
		log.Fatalf("panel: %v", err)
	}

	authSvc := auth.New(db, cfg, nil).WithSecretBox(box)

	if *bootstrap != "" {
		if err := bootstrapAdmin(context.Background(), db, authSvc, *bootstrap); err != nil {
			log.Fatalf("panel: bootstrap: %v", err)
		}
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
	})
	authSvc.Register(mux)
	// Unknown /api/ paths must stay JSON 404s, not fall through to the UI.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"not_found","message":"Unknown API endpoint."}}`)
	})
	mux.Handle("/", webui.Handler(web.Dist()))

	log.Printf("axionpanel panel %s listening on %s", version, *addr)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           webui.SecurityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	log.Fatal(srv.ListenAndServe())
}

// bootstrapAdmin creates the first administrator with a generated password,
// printed once to stdout. It refuses to run once any user exists, so it cannot
// be used to add a backdoor account to a configured panel.
func bootstrapAdmin(ctx context.Context, db *sql.DB, authSvc *auth.Service, username string) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("users already exist; bootstrap only runs on an empty panel")
	}
	password, err := auth.NewPassword()
	if err != nil {
		return err
	}
	user, err := authSvc.Create(ctx, username, password, "admin")
	if err != nil {
		return err
	}
	fmt.Printf("Created admin %q.\nPassword (shown once, not stored in plain text): %s\n", user.Username, password)
	return nil
}
