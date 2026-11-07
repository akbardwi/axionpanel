package siteapi

import (
	"axionpanel/internal/agentclient"
	"axionpanel/internal/auth"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Site struct {
	ServerID        int64  `json:"server_id"`
	ID              int64  `json:"id"`
	Domain          string `json:"domain"`
	Kind            string `json:"kind"`
	Root            string `json:"root"`
	Status          string `json:"status"`
	Listen          string `json:"listen,omitempty"`
	RetainedContent bool   `json:"retained_content"`
	LastError       string `json:"last_error,omitempty"`
	SystemUserID    *int64 `json:"system_user_id"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}
type Job struct {
	ServerID   int64           `json:"server_id"`
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Status     string          `json:"status"`
	Progress   int             `json:"progress"`
	Params     json.RawMessage `json:"params"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	ActorID    int64           `json:"actor_id"`
	CreatedAt  string          `json:"created_at"`
	StartedAt  string          `json:"started_at,omitempty"`
	FinishedAt string          `json:"finished_at,omitempty"`
}

const localServer = 1
const targetType = "static_site"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return "unknown"
}
func localOnly(r *http.Request) bool { v := r.URL.Query().Get("server_id"); return v == "" || v == "1" }

type decoded struct {
	Domain        string `json:"domain"`
	Kind          string `json:"kind"`
	Root          string `json:"root"`
	ServerID      *int64 `json:"server_id"`
	ConfirmDomain string `json:"confirm_domain"`
	DeleteFiles   *bool  `json:"delete_files"`
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		writeError(w, 400, "invalid_request", "Invalid JSON request.")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "invalid_request", "Invalid JSON request.")
		return false
	}
	return true
}

func decodedInput(w http.ResponseWriter, r *http.Request) (decoded, bool) {
	var d decoded
	if !decodeJSON(w, r, &d) {
		return d, false
	}
	if d.ServerID != nil && *d.ServerID != localServer {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return d, false
	}
	if d.Kind != "" && d.Kind != "static" {
		writeError(w, 400, "invalid_request", "Only static sites are supported.")
		return d, false
	}
	if d.Root != "" {
		writeError(w, 400, "invalid_request", "The panel derives the document root.")
		return d, false
	}
	return d, true
}

func domainOf(r *http.Request) string { return r.URL.Query().Get("domain") }

func (h *Handler) handlePlan(w http.ResponseWriter, r *http.Request) {
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	domain, err := NormalizeDomain(domainOf(r))
	if err != nil || domain == h.panel {
		writeError(w, 400, "invalid_domain", "Enter a lowercase DNS domain.")
		return
	}
	if h.agent == nil {
		writeError(w, 503, "agent_unavailable", "The host agent is not reachable.")
		return
	}
	var plan Plan
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	err = h.agent.Call(agentclient.WithActor(ctx, auth.SessionFrom(r.Context()).UserID), "site.plan", OperationParams{Domain: domain}, &plan)
	if err != nil {
		writeAgentError(w, err)
		return
	}
	if plan.Domain != domain || plan.Root == "" || plan.Listen == "" {
		writeError(w, 502, "agent_error", "The agent returned an invalid plan.")
		return
	}
	writeJSON(w, 200, plan)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	rows, err := h.db.QueryContext(r.Context(), `SELECT s.id,s.kind,s.root_dir,s.status,COALESCE(s.static_listen,''),COALESCE(s.last_error,''),s.system_user_id,s.created_at,s.updated_at,COALESCE((SELECT d.domain FROM site_domains d WHERE d.site_id=s.id AND d.is_primary=1),'') FROM sites s WHERE s.server_id=1 AND s.kind='static' AND s.status<>'deleted' ORDER BY s.id`)
	if err != nil {
		writeError(w, 500, "internal", "Inventory could not be read.")
		return
	}
	defer rows.Close()
	data := []Site{}
	for rows.Next() {
		var s Site
		var su sql.NullInt64
		if err := rows.Scan(&s.ID, &s.Kind, &s.Root, &s.Status, &s.Listen, &s.LastError, &su, &s.CreatedAt, &s.UpdatedAt, &s.Domain); err != nil {
			writeError(w, 500, "internal", "Inventory could not be read.")
			return
		}
		if su.Valid {
			v := su.Int64
			s.SystemUserID = &v
		}
		s.ServerID = 1
		data = append(data, s)
	}
	if err := rows.Err(); err != nil {
		writeError(w, 500, "internal", "Inventory could not be read.")
		return
	}
	writeJSON(w, 200, map[string]any{"data": data, "meta": map[string]any{"page": 1, "per_page": 50, "total": len(data)}})
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 404, "not_found", "Site not found.")
		return
	}
	s, err := h.siteRow(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "Site not found.")
		return
	}
	if err != nil {
		writeError(w, 500, "internal", "Site could not be read.")
		return
	}
	writeJSON(w, 200, s)
}

func (h *Handler) siteRow(ctx context.Context, id int64) (*Site, error) {
	var s Site
	var su sql.NullInt64
	err := h.db.QueryRowContext(ctx, `SELECT s.id,s.kind,s.root_dir,s.status,COALESCE(s.static_listen,''),COALESCE(s.last_error,''),s.system_user_id,s.created_at,s.updated_at,COALESCE((SELECT d.domain FROM site_domains d WHERE d.site_id=s.id AND d.is_primary=1),'') FROM sites s WHERE s.id=? AND s.server_id=1 AND s.kind='static'`, id).Scan(&s.ID, &s.Kind, &s.Root, &s.Status, &s.Listen, &s.LastError, &su, &s.CreatedAt, &s.UpdatedAt, &s.Domain)
	if err != nil {
		return nil, err
	}
	if su.Valid {
		v := su.Int64
		s.SystemUserID = &v
	}
	s.ServerID = 1
	s.RetainedContent = s.Status == "deleted"
	return &s, nil
}

func (h *Handler) handleJob(w http.ResponseWriter, r *http.Request) {
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	id := r.PathValue("id")
	if !ValidOperationID(id) {
		writeError(w, 404, "not_found", "Job not found.")
		return
	}
	j, err := h.jobRow(r.Context(), id)
	sess := auth.SessionFrom(r.Context())
	if err == nil && j.ActorID != sess.UserID && sess.User.Role != "admin" {
		writeError(w, 404, "not_found", "Job not found.")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "Job not found.")
		return
	}
	if err != nil {
		writeError(w, 500, "internal", "Job could not be read.")
		return
	}
	writeJSON(w, 200, j)
}
func (h *Handler) jobRow(ctx context.Context, id string) (*Job, error) {
	var j Job
	var params string
	var res, start, fin sql.NullString
	err := h.db.QueryRowContext(ctx, `SELECT j.id,j.type,j.status,j.progress,j.params,j.result,COALESCE(j.error,''),COALESCE(j.user_id,0),j.created_at,j.started_at,j.finished_at FROM jobs j WHERE j.id=? AND j.server_id=1 AND j.target_type='static_site' AND j.type IN ('site.apply','site.remove')`, id).Scan(&j.ID, &j.Type, &j.Status, &j.Progress, &params, &res, &j.Error, &j.ActorID, &j.CreatedAt, &start, &fin)
	if err != nil {
		return nil, err
	}
	if res.Valid {
		j.Result = json.RawMessage(res.String)
	}
	j.Params = json.RawMessage(params)
	j.ServerID = 1
	j.StartedAt = start.String
	j.FinishedAt = fin.String
	return &j, nil
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		writeError(w, 503, "agent_unavailable", "The host agent is not reachable.")
		return
	}
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	sess := auth.SessionFrom(r.Context())
	d, ok := decodedInput(w, r)
	if !ok {
		return
	}
	domain, err := NormalizeDomain(d.Domain)
	if err != nil || domain == h.panel {
		writeError(w, 400, "invalid_domain", "Enter a lowercase DNS domain.")
		return
	}
	tx, _, ok := h.auth.MutationTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	var exists int
	err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM site_domains WHERE domain=?`, domain).Scan(&exists)
	if err != nil {
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	if exists > 0 {
		writeError(w, 409, "domain_conflict", "That domain is already in use.")
		return
	}
	opID, err := NewOperationID()
	if err != nil {
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	root := "" // Agent owns paths; observed by the safe plan before dispatch.
	res, err := tx.Exec(`INSERT INTO sites(server_id,owner_user_id,system_user_id,kind,root_dir,status) VALUES(1,?,NULL,'static',?,'provisioning')`, sess.UserID, root)
	if err != nil {
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	siteID, err := res.LastInsertId()
	if err != nil {
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	if _, err = tx.Exec(`INSERT INTO site_domains(site_id,domain,is_primary) VALUES(?,?,1)`, siteID, domain); err != nil {
		if isUnique(err) {
			writeError(w, 409, "domain_conflict", "That domain is already in use.")
			return
		}
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	params, _ := json.Marshal(map[string]any{"domain": domain, "operation_id": opID})
	if _, err = tx.Exec(`INSERT INTO jobs(id,server_id,user_id,type,target_type,target_id,status,progress,params,started_at) VALUES(?,1,?,'site.apply',?,?, 'running',0,?,?)`, opID, sess.UserID, targetType, strconv.FormatInt(siteID, 10), string(params), now); err != nil {
		writeError(w, 500, "internal", "The site could not be reserved.")
		return
	}
	if err = appendAudit(r.Context(), tx, &AuditEvent{ActorID: sess.UserID, Username: sess.User.Username, Action: "site.create", Outcome: "success", Target: targetType, TargetID: opID, IP: peerIP(r), Details: map[string]any{"site_id": siteID, "domain": domain}}); err != nil {
		writeError(w, 500, "internal", "The change was not recorded and nothing was applied.")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal", "The change was not recorded and nothing was applied.")
		return
	}
	result, agentErr := h.dispatch(r.Context(), sess.UserID, "site.apply", domain, opID)
	if err := h.finish(r.Context(), siteID, opID, "site.apply", domain, result, agentErr); err != nil {
		writeError(w, 500, "manual_reconciliation", "The outcome could not be recorded; reconcile the durable operation before retrying.")
		return
	}
	site, _ := h.siteRow(r.Context(), siteID)
	job, _ := h.jobRow(r.Context(), opID)
	writeJSON(w, 200, map[string]any{"site": site, "job": job, "mode": "synchronous"})
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		writeError(w, 503, "agent_unavailable", "The host agent is not reachable.")
		return
	}
	if !localOnly(r) {
		writeError(w, 400, "invalid_server", "Only the local server is supported.")
		return
	}
	sess := auth.SessionFrom(r.Context())
	d, ok := decodedInput(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Has("delete_files") || d.DeleteFiles != nil {
		writeError(w, 400, "delete_files_forbidden", "Deleting site files is not supported; content is retained.")
		return
	}
	if d.ConfirmDomain == "" {
		writeError(w, 400, "confirmation_required", "Type the exact domain to confirm removal.")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 404, "not_found", "Site not found.")
		return
	}
	tx, _, ok := h.auth.MutationTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	var domain, status string
	err = tx.QueryRow(`SELECT COALESCE((SELECT d.domain FROM site_domains d WHERE d.site_id=s.id AND d.is_primary=1),''),s.status FROM sites s WHERE s.id=? AND s.server_id=1 AND s.kind='static'`, id).Scan(&domain, &status)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "not_found", "Site not found.")
		return
	}
	if err != nil {
		writeError(w, 500, "internal", "The site could not be read.")
		return
	}
	if status == "deleted" {
		writeError(w, 409, "site_deleted", "This site is already removed; its content is retained.")
		return
	}
	if status != "active" && status != "error" {
		writeError(w, 409, "reconciliation_required", "Only an active or failed site may be removed; reconcile unfinished work first.")
		return
	}
	if d.ConfirmDomain != domain {
		writeError(w, 400, "confirmation_mismatch", "Type the exact domain to confirm removal.")
		return
	}
	opID, err := NewOperationID()
	if err != nil {
		writeError(w, 500, "internal", "The removal could not be reserved.")
		return
	}
	params, _ := json.Marshal(map[string]any{"domain": domain, "operation_id": opID})
	if _, err = tx.Exec(`INSERT INTO jobs(id,server_id,user_id,type,target_type,target_id,status,progress,params,started_at) VALUES(?,1,?,'site.remove',?,?, 'running',0,?,?)`, opID, sess.UserID, targetType, strconv.FormatInt(id, 10), string(params), now); err != nil {
		writeError(w, 500, "internal", "The removal could not be reserved.")
		return
	}
	if _, err = tx.Exec(`UPDATE sites SET status='deleting',updated_at=? WHERE id=?`, now, id); err != nil {
		writeError(w, 500, "internal", "The removal could not be reserved.")
		return
	}
	if err = appendAudit(r.Context(), tx, &AuditEvent{ActorID: sess.UserID, Username: sess.User.Username, Action: "site.remove", Outcome: "success", Target: targetType, TargetID: opID, IP: peerIP(r), Details: map[string]any{"site_id": id, "domain": domain}}); err != nil {
		writeError(w, 500, "internal", "The change was not recorded and nothing was applied.")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "internal", "The change was not recorded and nothing was applied.")
		return
	}
	result, agentErr := h.dispatch(r.Context(), sess.UserID, "site.remove", domain, opID)
	if err := h.finish(r.Context(), id, opID, "site.remove", domain, result, agentErr); err != nil {
		writeError(w, 500, "manual_reconciliation", "The outcome could not be recorded; reconcile the durable operation before retrying.")
		return
	}
	site, _ := h.siteRow(r.Context(), id)
	job, _ := h.jobRow(r.Context(), opID)
	retained := job != nil && job.Status == "succeeded"
	writeJSON(w, 200, map[string]any{"site": site, "job": job, "retained_content": retained, "mode": "synchronous"})
}

func (h *Handler) dispatch(ctx context.Context, actor int64, op, domain, opID string) (Result, error) {
	if h.agent == nil {
		return Result{}, agentclient.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var plan Plan
	if op == "site.apply" {
		if err := h.agent.Call(agentclient.WithActor(ctx, actor), "site.plan", OperationParams{Domain: domain}, &plan); err != nil {
			return Result{}, err
		}
		if plan.Domain != domain || plan.Root == "" || plan.Listen == "" {
			return Result{}, errInvalidAgentResult
		}
		if _, err := h.db.ExecContext(ctx, `UPDATE sites SET root_dir=?,static_listen=? WHERE server_id=1 AND kind='static' AND id=(SELECT CAST(target_id AS INTEGER) FROM jobs WHERE id=?)`, plan.Root, plan.Listen, opID); err != nil {
			return Result{}, err
		}
	}
	var res Result
	err := h.agent.Call(agentclient.WithActor(ctx, actor), op, OperationParams{Domain: domain, OperationID: opID}, &res)
	if err != nil {
		return Result{}, err
	}
	if res.Domain != domain || res.OperationID != opID {
		return Result{}, errInvalidAgentResult
	}
	switch op {
	case "site.apply":
		if res.Status != "applied" {
			return Result{}, errInvalidAgentResult
		}
	case "site.remove":
		if res.Status != "removed" && res.Status != "absent" {
			return Result{}, errInvalidAgentResult
		}
	}
	return res, nil
}

var errInvalidAgentResult = errors.New("siteapi: invalid agent result")

func (h *Handler) finish(ctx context.Context, siteID int64, opID, op, domain string, result Result, agentErr error) error {
	// Record a known outcome even if the HTTP caller disconnected, with a bound.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if agentErr != nil {
		code := classify(agentErr)
		if _, err = tx.ExecContext(ctx, `UPDATE sites SET status='error',last_error=?,updated_at=? WHERE id=?`, code, now, siteID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE jobs SET status='failed',progress=100,error=?,finished_at=? WHERE id=? AND status='running'`, code, now, opID); err != nil {
			return err
		}
	} else {
		status := "active"
		if op == "site.remove" {
			status = "deleted"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE sites SET status=?,last_error=NULL,updated_at=? WHERE id=?`, status, now, siteID); err != nil {
			return err
		}
		b, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE jobs SET status='succeeded',progress=100,result=?,finished_at=? WHERE id=? AND status='running'`, string(b), now, opID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// classify separates a definite agent rejection from an unknown transport
// outcome. Ambiguity is never reported as success or as a rollback.
func classify(err error) string {
	var ae *agentclient.Error
	if !errors.As(err, &ae) {
		return "manual_reconciliation"
	}
	switch ae.Code {
	case "invalid_params", "forbidden_by_policy", "not_found", "conflict", "unsupported", "preexisting_config_error", "config_test_failed":
		return ae.Code
	}
	return "agent_error"
}

func writeAgentError(w http.ResponseWriter, err error) {
	var ae *agentclient.Error
	if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
		msg := ae.Message
		if msg == "" {
			msg = "The agent rejected the request."
		}
		writeError(w, ae.Status, ae.Code, msg)
		return
	}
	writeError(w, 503, "agent_unavailable", "The host agent is not reachable.")
}

func isUnique(err error) bool { return strings.Contains(err.Error(), "UNIQUE constraint failed") }
