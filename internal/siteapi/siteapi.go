// Package siteapi implements the local-only static website metadata API.
// Mutations execute synchronously after durable intent; no background work or
// automatic replay is claimed. Jobs use random 32-lowercase-hex identities.
package siteapi

import (
	"axionpanel/internal/auth"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

// Agent is the injectable call boundary. Production wiring may use the real
// Unix-socket client; tests use a deterministic recorder.
type Agent interface {
	Call(context.Context, string, any, any) error
}

type Plan struct {
	Domain  string `json:"domain"`
	Vhost   string `json:"vhost"`
	Root    string `json:"root"`
	Listen  string `json:"listen"`
	Applied bool   `json:"applied"`
	WouldDo string `json:"would_do"`
}
type Result struct {
	Domain      string `json:"domain"`
	OperationID string `json:"operation_id,omitempty"`
	Status      string `json:"status"`
	Changed     bool   `json:"changed"`
}
type OperationParams struct {
	Domain      string `json:"domain"`
	OperationID string `json:"operation_id,omitempty"`
}
type Handler struct {
	db    *sql.DB
	agent Agent
	auth  *auth.Service
	panel string
}

// New requires migrations already applied and must be called once at process
// startup before serving. It marks interrupted local static jobs failed without
// dispatch/replay. nil agent permits local inventory while plans fail closed.
func New(db *sql.DB, agent Agent, authSvc *auth.Service) (*Handler, error) {
	if db == nil || authSvc == nil {
		return nil, errors.New("siteapi: database and auth required")
	}
	h := &Handler{db: db, agent: agent, auth: authSvc, panel: authSvc.PanelHostname()}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = tx.Exec(`UPDATE sites SET status='error',last_error='interrupted_manual_reconciliation',updated_at=? WHERE kind='static' AND server_id=1 AND id IN (SELECT CAST(target_id AS INTEGER) FROM jobs WHERE server_id=1 AND target_type='static_site' AND status IN ('queued','running'))`, now)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE jobs SET status='failed',error='interrupted_manual_reconciliation',finished_at=? WHERE server_id=1 AND target_type='static_site' AND status IN ('queued','running')`, now)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return h, nil
}
func (h *Handler) Register(mux *http.ServeMux) {
	for path, fn := range map[string]http.HandlerFunc{"/api/v1/sites": h.handleList, "/api/v1/sites/plan": h.handlePlan, "/api/v1/sites/{id}": h.handleGet, "/api/v1/jobs/{id}": h.handleJob} {
		mux.Handle("GET "+path, h.auth.RequireAuth(fn))
	}
	mux.Handle("POST /api/v1/sites", h.auth.RequireMutation(http.HandlerFunc(h.handleCreate)))
	mux.Handle("DELETE /api/v1/sites/{id}", h.auth.RequireMutation(http.HandlerFunc(h.handleDelete)))
}
