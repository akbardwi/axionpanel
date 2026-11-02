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

	"axionpanel/internal/auth"
	"axionpanel/internal/store"
)

var version = "0.0.0-dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7800", "listen address")
	dbPath := flag.String("db", "panel.db", "SQLite metadata database path")
	bootstrap := flag.String("bootstrap-admin", "", "create the first admin user with this username, print a generated password, and exit")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("panel: %v", err)
	}
	defer db.Close()
	if err := store.Migrate(context.Background(), db); err != nil {
		log.Fatalf("panel: %v", err)
	}

	authSvc := auth.New(db, auth.DefaultConfig(), nil)

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

	log.Printf("axionpanel panel %s listening on %s", version, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
