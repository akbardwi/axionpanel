// Package systemapi exposes the local host's read-only agent data to the
// authenticated panel UI. It never exposes the agent socket and never invents
// data: if the agent is unreachable the API says so instead of returning zeros.
package systemapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"axionpanel/internal/agentclient"
)

// Client is the subset of the agent client this API needs.
type Client interface {
	Info(ctx context.Context) (*agentclient.Info, error)
	Stats(ctx context.Context) (*agentclient.Stats, error)
}

// Handler serves /api/v1/system/*. The auth middleware is supplied by the
// caller so this package never decides who is signed in.
type Handler struct {
	Client Client
}

// Register mounts the routes. wrap must enforce authentication; a nil wrap is
// a programming error and panics rather than serving host data unauthenticated.
func (h *Handler) Register(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	if h.Client == nil || wrap == nil {
		panic("systemapi: Client and auth wrapper are required")
	}
	mux.Handle("GET /api/v1/system/info", wrap(http.HandlerFunc(h.handleInfo)))
	mux.Handle("GET /api/v1/system/stats", wrap(http.HandlerFunc(h.handleStats)))
	mux.Handle("GET /api/v1/system/agent", wrap(http.HandlerFunc(h.handleStatus)))
	// Method-specific GET patterns do not cover other verbs: a POST would fall
	// through to the panel's /api/ 404. Mount an explicit 405 for the same
	// paths so a wrong method is unambiguous and carries Allow.
	for _, path := range []string{"/api/v1/system/info", "/api/v1/system/stats", "/api/v1/system/agent"} {
		mux.Handle(path, wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		})))
	}
}

func (h *Handler) handleInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.Client.Info(r.Context())
	if err != nil {
		writeAgentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Connected bool `json:"connected"`
		*agentclient.Info
	}{true, info})
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.Client.Stats(r.Context())
	if err != nil {
		writeAgentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleStatus is the connection probe. An unreachable agent is a normal state
// for the UI, so it answers 200 with connected=false instead of an error.
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	info, err := h.Client.Info(r.Context())
	if err != nil {
		reason := "agent_error"
		if errors.Is(err, agentclient.ErrUnavailable) {
			reason = "agent_unavailable"
		}
		writeJSON(w, http.StatusOK, map[string]any{"connected": false, "reason": reason})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connected":           true,
		"version":             info.Version,
		"protocol":            info.Protocol,
		"capability_revision": info.CapabilityRevision,
		"observed_at":         info.ObservedAt,
	})
}

func writeAgentError(w http.ResponseWriter, err error) {
	var opErr *agentclient.Error
	switch {
	case errors.As(err, &opErr):
		code := opErr.Code
		status := opErr.Status
		message := opErr.Message
		if message == "" {
			message = "The agent rejected the request."
		}
		// Agent-internal failures stay generic: their details can describe
		// host paths and are not the panel's to disclose.
		if status >= http.StatusInternalServerError && status != http.StatusNotImplemented {
			writeError(w, http.StatusBadGateway, "agent_error", "The agent could not complete the request.")
			return
		}
		switch {
		case (status >= http.StatusBadRequest && status < http.StatusInternalServerError) || status == http.StatusNotImplemented:
			// Valid agent 4xx/501 errors pass through. agentclient validates
			// the envelope; the agent server sanitizes the message.
			writeError(w, status, code, message)
		default:
			writeError(w, http.StatusBadGateway, "agent_error", "The agent rejected the request.")
		}
	default:
		// Transport, protocol and malformed-response failures all mean the
		// panel cannot read the host right now. No internal detail is echoed.
		writeError(w, http.StatusServiceUnavailable, "agent_unavailable", "The host agent is not reachable.")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
