package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// auditRecord is the complete, fixed-shape agent audit event. There is
// deliberately no params, result, header, body, path or free-form error field:
// untrusted request data cannot reach the audit log.
type auditRecord struct {
	Event          string  `json:"event"`
	Outcome        string  `json:"outcome"`
	Operation      string  `json:"operation"`
	Classification string  `json:"classification"`
	Target         string  `json:"target,omitempty"`
	RequestID      string  `json:"request_id,omitempty"`
	Actor          string  `json:"actor,omitempty"`
	PeerUID        *uint32 `json:"peer_uid,omitempty"`
	DurationMS     int64   `json:"duration_ms"`
	Code           string  `json:"error_code,omitempty"`
}

// auditCodes is the closed set of error codes allowed in a record. A handler
// that returns an invented OpError code is logged as internal instead.
var auditCodes = map[string]bool{
	ErrInvalidParams: true, ErrProtocolMismatch: true, ErrForbiddenByPolicy: true,
	ErrNotFound: true, ErrConflict: true, ErrPreexistingConfig: true,
	ErrConfigTestFailed: true, ErrUnsupported: true, ErrInternal: true,
	ErrPayloadTooLarge: true, ErrTooManyRequests: true, ErrUnauthorized: true,
	ErrMethodNotAllowed: true, ErrCapabilityUnavailable: true,
}

// requestAudit lives only for one request and contains fixed, validated fields.
type requestAudit struct{ record auditRecord }
type auditContextKey struct{}

func (s *Server) auditEvent(rec auditRecord) {
	if s.Logger == nil {
		return
	}
	// Logger has no error result. A panic must not leak raw logger/handler data.
	defer func() { _ = recover() }()
	b, _ := json.Marshal(rec)
	s.Logger("%s", b)
}

func operationAudit(ctx context.Context, name string, p Permission, known bool) {
	a, ok := ctx.Value(auditContextKey{}).(*requestAudit)
	if !ok {
		return
	}
	a.record.Operation = "unknown"
	a.record.Classification = "unclassified"
	if known {
		a.record.Operation = name
		if p.valid() {
			a.record.Classification = string(p)
			if target, ok := strings.CutPrefix(string(p), "service:"); ok {
				a.record.Classification = "service"
				a.record.Target = target
			}
		}
	}
}

type auditResponse struct {
	http.ResponseWriter
	status int
	code   string
}

func (w *auditResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *auditResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *auditResponse) setErrorCode(code string) {
	if !auditCodes[code] {
		code = ErrInternal
	}
	w.code = code
}

func actualPeerUID(ctx context.Context) uint32 { uid, _ := peerUIDFromContext(ctx); return uid }

type peerUIDContextKey struct{}

type peerConn struct {
	net.Conn
	uid uint32
}

// peerUIDFromContext returns the kernel-reported UID recorded by ConnContext.
// The bool is false for tests that call Handler directly without a socket.
func peerUIDFromContext(ctx context.Context) (uint32, bool) {
	uid, ok := ctx.Value(peerUIDContextKey{}).(uint32)
	return uid, ok
}

// connContext records the SO_PEERCRED UID on the connection context so audit
// records carry the real peer identity rather than the configured allow-list
// value. Nothing in the request can influence it.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*peerConn); ok {
		return context.WithValue(ctx, peerUIDContextKey{}, pc.uid)
	}
	return ctx
}
