package main

import (
	"database/sql"
	"net/http"
	"time"

	"axionpanel/internal/agentclient"
	"axionpanel/internal/auth"
	"axionpanel/internal/siteapi"
)

// siteAgentTimeout bounds one agent round trip made on behalf of a website
// request. Static plan/apply is dominated by `nginx -t` and a reload, so the
// client ceiling is slightly above the handler's 90s dispatch budget.
const siteAgentTimeout = 95 * time.Second

// registerSiteRoutes mounts the static website API. Inventory always works so
// the panel can show what it knows; plan/apply fail closed with an agent error
// when the operator did not opt the agent into static sites.
func registerSiteRoutes(mux *http.ServeMux, db *sql.DB, authSvc *auth.Service, socket string) error {
	client := agentclient.New(socket)
	client.Timeout = siteAgentTimeout
	handler, err := siteapi.New(db, client, authSvc)
	if err != nil {
		return err
	}
	handler.Register(mux)
	return nil
}
