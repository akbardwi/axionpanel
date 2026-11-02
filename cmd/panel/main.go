// Command panel runs the AxionPanel API server and web UI.
// It runs unprivileged and delegates system operations to the agent.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

var version = "0.0.0-dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7800", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
	})

	log.Printf("axionpanel panel %s listening on %s", version, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
