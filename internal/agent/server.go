package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Protocol is the value this build speaks. A panel with a different
	// protocol version is rejected with protocol_mismatch.
	Protocol = 1

	maxOpBodyBytes = 1 << 20
	opTimeout      = 60 * time.Second
)

// Version is the agent build version. It is a variable so releases can stamp
// it with -X axionpanel/internal/agent.Version=<tag>; the CLI reads it so the
// daemon banner and /v1/info can never disagree.
var Version = "0.1.0-dev"

// Server is the local agent API. It serves HTTP over a Unix socket and honors
// only connections whose kernel-reported peer UID matches AllowedUID. A peer
// with uid 0 is always rejected unless AllowRootPeer is set, so the zero value
// of Server can never admit root.
type Server struct {
	// Registry and Policy are startup-only configuration. The first
	// Handler/dispatch call snapshots both; later registrations cannot widen
	// this server's catalog, and no API can reload or relax its policy.
	Registry   *Registry
	Policy     Policy
	policyOnce sync.Once
	policy     Policy
	operations map[string]registeredOperation
	Socket     string
	// SocketGID owns the socket and its directory. Zero means the process
	// effective GID; the CLI always requires an explicit panel group.
	SocketGID  int
	AllowedUID uint32
	// AllowRootPeer admits a peer with uid 0, and only when AllowedUID is also
	// 0. It exists solely for tests and E2E harnesses that run as root; the
	// agent binary never sets it, and production must leave it false.
	AllowRootPeer   bool
	ShutdownTimeout time.Duration // defaults to five seconds
	Logger          func(string, ...any)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger(format, args...)
	}
}

// Listen pins each directory with openat(O_NOFOLLOW). Existing endpoints,
// including stale sockets, require manual operator cleanup; never dial/unlink.
// Existing directories are validated, never chmodded or chowned. Ancestors
// must belong to root or this euid and not be group/world writable; root-owned
// sticky ancestors (e.g. /tmp) are allowed, but never as the direct parent.
// The direct parent must also carry the socket gid; both an agent-created
// euid:gid 0750 directory and a systemd RuntimeDirectory root:gid 0755 qualify.
func (s *Server) Listen(ctx context.Context) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(s.Socket) || filepath.Clean(s.Socket) != s.Socket || len(s.Socket) > 107 {
		return nil, errors.New("agent: clean absolute Unix socket path required (max 107 bytes)")
	}
	if s.SocketGID < 0 {
		return nil, errors.New("agent: invalid socket gid")
	}
	gid := s.SocketGID
	if gid == 0 {
		gid = os.Getegid()
	}
	dir, name := filepath.Dir(s.Socket), filepath.Base(s.Socket)
	fd, err := secureSocketDir(dir, gid)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(fd)
		}
	}()
	var st unix.Stat_t
	if err = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return nil, errors.New("agent: endpoint exists; manual operator cleanup required")
	} else if err != unix.ENOENT {
		return nil, err
	}
	// /proc/self/fd anchors bind and metadata changes to the validated directory,
	// even if an ancestor is renamed after validation. Linux-only transport.
	anchored := fmt.Sprintf("/proc/self/fd/%d/%s", fd, name)
	// Brief window: the socket exists with umask-derived mode and euid:egid
	// ownership between bind and the fchown/fchmod below. Harmless because the
	// direct parent is not group/world writable and every accepted conn is
	// SO_PEERCRED-checked before any HTTP parsing, regardless of socket mode.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: anchored, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	cleanup := func() { ln.Close(); unix.Unlinkat(fd, name, 0) }
	if err = unix.Fchownat(fd, name, os.Geteuid(), gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		cleanup()
		return nil, err
	}
	if err = unix.Fchmodat(fd, name, 0660, 0); err != nil {
		cleanup()
		return nil, err
	}
	keep = true
	return &socketListener{UnixListener: ln, dirfd: fd, name: name, path: s.Socket}, nil
}

func secureSocketDir(path string, gid int) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) { unix.Close(fd); return -1, err }
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		return fail(errors.New("agent: insecure root directory"))
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		created := false
		if e == unix.ENOENT {
			// Only create below a pinned, validated parent. Sticky parent cannot
			// replace our newly created directory; its ownership is checked below.
			if e = unix.Mkdirat(fd, part, 0750); e != nil {
				return fail(e)
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			created = true
		}
		if e != nil {
			return fail(fmt.Errorf("agent: unsafe socket directory: %w", e))
		}
		unix.Close(fd)
		fd = next
		if created {
			if e = unix.Fchown(fd, os.Geteuid(), gid); e != nil {
				return fail(e)
			}
			if e = unix.Fchmod(fd, 0750); e != nil {
				return fail(e)
			}
		}
		if e = unix.Fstat(fd, &st); e != nil {
			return fail(e)
		}
		direct := i == len(parts)-1
		// A direct parent may be owned by this euid or by root: systemd
		// RuntimeDirectory=root-owned dirs with Group=<panel> are the documented
		// deploy shape, and when the agent itself is root both are the same uid.
		owned := st.Uid == uint32(os.Geteuid()) || st.Uid == 0
		groupOrWorldWritable := st.Mode&0022 != 0
		sticky := !direct && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if !owned || (groupOrWorldWritable && !sticky) {
			return fail(errors.New("agent: insecure socket directory ownership or mode (must be owned by agent or root and not group/world writable)"))
		}
		// The direct parent gates socket replacement, so it must share the socket
		// group and never let that group write. Exact bits (0750 vs root 0755)
		// are not pinned: the socket is 0660 and every conn is peer-checked.
		if direct && st.Gid != uint32(gid) {
			return fail(fmt.Errorf("agent: socket parent gid %d does not match socket gid %d", st.Gid, gid))
		}
	}
	if path == "/" {
		return fail(errors.New("agent: root cannot be socket parent"))
	}
	return fd, nil
}

type socketListener struct {
	*net.UnixListener
	dirfd      int
	name, path string
	once       sync.Once
	closeErr   error
}

func (l *socketListener) Addr() net.Addr { return &net.UnixAddr{Name: l.path, Net: "unix"} }
func (l *socketListener) Close() error {
	l.once.Do(func() {
		l.closeErr = l.UnixListener.Close()
		_ = unix.Unlinkat(l.dirfd, l.name, 0)
		_ = unix.Close(l.dirfd)
	})
	return l.closeErr
}

// Serve accepts connections until ctx is cancelled. Each connection is checked
// before any HTTP parsing, so an unauthorized peer never reaches a handler.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	handler := s.Handler()
	srv := &http.Server{
		Handler:     handler,
		ConnContext: connContext,
		// Handlers must not inherit signal cancellation: ctx stops the accept
		// loop (via Shutdown below), while in-flight operations keep running
		// until they finish or ShutdownTimeout forces srv.Close().
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * opTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		<-runCtx.Done()
		timeout := s.ShutdownTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			// Shutdown deadline exceeded: force-close remaining connections so
			// the caller and tests never leak goroutines.
			_ = srv.Close()
		}
		shutdownErr <- err
	}()
	err := srv.Serve(&peerCheckedListener{Listener: ln, allowed: s.AllowedUID, allowRoot: s.AllowRootPeer, logf: s.logf})
	stop()
	serr := <-shutdownErr
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if err == nil && serr != nil && !errors.Is(serr, context.Canceled) {
		s.logf("agent: shutdown deadline exceeded; active connections closed")
	}
	return err
}

type peerCheckedListener struct {
	net.Listener
	allowed   uint32
	allowRoot bool
	logf      func(string, ...any)
}

// Accept rejects unauthorized peers immediately. A delay here would let one
// foreign UID with socket-group access stall admission for every queued peer,
// so rejection stays O(1) and the backlog bounds queued work. The socket is
// 0660 group-restricted, which is the primary flood boundary.
func (l *peerCheckedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		uid, err := PeerUID(uc)
		if err != nil {
			l.logf("agent: dropping connection without peer credentials: %v", err)
			conn.Close()
			continue
		}
		if uid == 0 && !l.allowRoot {
			l.logf("agent: rejecting connection from uid 0 (root peers disabled)")
			conn.Close()
			continue
		}
		if uid != l.allowed {
			l.logf("agent: rejecting connection from uid %d", uid)
			conn.Close()
			continue
		}
		return &peerConn{Conn: conn, uid: uid}, nil
	}
}

// Handler returns the HTTP API. Header validation happens before routing so
// every response carries a protocol-level error shape.
func (s *Server) Handler() http.Handler {
	s.policySnapshot()
	return s.protocolMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := ""
		if r.URL.Path == "/v1/info" {
			allowed = "GET"
			if r.Method == allowed {
				s.handleInfo(w, r)
				return
			}
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/v1/ops/"); ok && name != "" && !strings.Contains(name, "/") {
			allowed = "POST"
			if r.Method == allowed {
				r.SetPathValue("name", name)
				s.handleOp(w, r)
				return
			}
		}
		if allowed != "" {
			w.Header().Set("Allow", allowed)
			writeError(w, newOpError(ErrMethodNotAllowed, "method not allowed", nil))
			return
		}
		writeError(w, newOpError(ErrNotFound, "unknown endpoint", nil))
	}))
}

func (s *Server) protocolMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		a := &requestAudit{record: auditRecord{Event: "agent.request", Operation: "unknown", Classification: "unclassified"}}
		if uid, ok := peerUIDFromContext(r.Context()); ok {
			a.record.PeerUID = &uid
		}
		r = r.WithContext(context.WithValue(r.Context(), auditContextKey{}, a))
		aw := &auditResponse{ResponseWriter: w}
		w = aw
		defer func() {
			a.record.DurationMS = time.Since(started).Milliseconds()
			a.record.Outcome = "success"
			if aw.code != "" {
				a.record.Outcome = "failed"
			}
			if aw.code == ErrForbiddenByPolicy || aw.code == ErrNotFound || aw.code == ErrUnauthorized || aw.code == ErrUnsupported || aw.code == ErrCapabilityUnavailable {
				a.record.Outcome = "denied"
			}
			a.record.Code = aw.code
			s.auditEvent(a.record)
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Axion-Protocol", strconv.Itoa(Protocol))
		// Echo only an already-validated request ID; rejected input is not reflected.
		setEchoRequestID(w, r.Header)

		defer func() {
			if rec := recover(); rec != nil {
				// Panic data, method and paths are never logged.
				writeError(w, newOpError(ErrInternal, "unexpected failure", nil))
			}
		}()

		if err := validateAxionHeaders(r.Header); err != nil {
			writeError(w, err)
			return
		}
		if a, ok := r.Context().Value(auditContextKey{}).(*requestAudit); ok {
			a.record.RequestID = r.Header.Get("Axion-Request-ID")
			a.record.Actor = r.Header.Get("Axion-Actor")
		}
		next.ServeHTTP(w, r)
	})
}

func setEchoRequestID(w http.ResponseWriter, h http.Header) {
	if v := h.Get("Axion-Request-ID"); validRequestID(v) {
		w.Header().Set("Axion-Request-ID", v)
	}
}

var (
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	axionHeaderPattern = regexp.MustCompile(`^Axion-(Protocol|Actor|Request-Id)$`)
)

func validRequestID(v string) bool { return requestIDPattern.MatchString(v) }

func validateAxionHeaders(h http.Header) error {
	for name, vals := range h {
		if strings.HasPrefix(strings.ToLower(name), "axion-") {
			if !axionHeaderPattern.MatchString(name) {
				return invalidParams(map[string]string{"header": name, "reason": "unknown header"})
			}
			if len(vals) != 1 {
				return invalidParams(map[string]string{"header": name, "reason": "duplicate header"})
			}
		}
	}
	if err := validateProtocol(h.Values("Axion-Protocol")); err != nil {
		return err
	}
	if err := validateActor(h.Values("Axion-Actor")); err != nil {
		return err
	}
	if err := validateRequestID(h.Values("Axion-Request-ID")); err != nil {
		return err
	}
	return nil
}

func validateProtocol(vals []string) error {
	if len(vals) == 0 {
		return newOpError(ErrProtocolMismatch, "unsupported protocol version", map[string]string{"want": strconv.Itoa(Protocol), "got": ""})
	}
	if len(vals) > 1 {
		return invalidParams(map[string]string{"header": "Axion-Protocol", "reason": "duplicate header"})
	}
	if vals[0] != strconv.Itoa(Protocol) {
		return newOpError(ErrProtocolMismatch, "unsupported protocol version", map[string]string{"want": strconv.Itoa(Protocol), "got": vals[0]})
	}
	return nil
}

func validateActor(vals []string) error {
	if len(vals) == 0 {
		return invalidParams(map[string]string{"header": "Axion-Actor", "reason": "required"})
	}
	if len(vals) > 1 {
		return invalidParams(map[string]string{"header": "Axion-Actor", "reason": "duplicate header"})
	}
	v := vals[0]
	n, err := strconv.ParseUint(v, 10, 63)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != v {
		return invalidParams(map[string]string{"header": "Axion-Actor", "reason": "positive numeric actor required"})
	}
	return nil
}

func validateRequestID(vals []string) error {
	if len(vals) == 0 {
		return invalidParams(map[string]string{"header": "Axion-Request-ID", "reason": "required"})
	}
	if len(vals) > 1 {
		return invalidParams(map[string]string{"header": "Axion-Request-ID", "reason": "duplicate header"})
	}
	if !validRequestID(vals[0]) {
		return invalidParams(map[string]string{"header": "Axion-Request-ID", "reason": "must be 1-128 printable safe characters"})
	}
	return nil
}

func (s *Server) requestMeta(r *http.Request) RequestMeta {
	return RequestMeta{RequestID: r.Header.Get("Axion-Request-ID"), Actor: r.Header.Get("Axion-Actor"), PeerUID: actualPeerUID(r.Context())}
}

// dispatch is the canonical execution path for both HTTP endpoints. Registry.Run
// uses this same path with deny-by-default policy, so it cannot bypass policy.
func (s *Server) dispatch(ctx context.Context, name string, params Params, meta RequestMeta) (result any, err error) {
	s.policySnapshot()
	defer func() {
		if recover() != nil {
			result = nil
			err = newOpError(ErrInternal, "unexpected failure", nil)
		}
	}()
	op, ok := s.operations[name]
	operationAudit(ctx, name, op.permission, ok)
	if !ok {
		return nil, newOpError(ErrNotFound, "operation is not in the agent catalog", nil)
	}
	if !op.permission.valid() || !s.policyAllows(op.permission) {
		return nil, newOpError(ErrForbiddenByPolicy, "operation denied by host policy", nil)
	}
	// Logger is best-effort (no error return), not a durable mutation audit.
	// Until a checked durable sink exists, privileged handlers never execute,
	// even if host policy permits them. No generic shell is auto-authorized.
	if op.permission != ReadOnly {
		return nil, newOpError(ErrUnsupported, "privileged operations are not implemented", nil)
	}
	return op.handler(ctx, params, meta)
}

// noteOperation records the fixed startup classification before any request
// body is parsed, so a malformed body still audits a trustworthy operation.
func (s *Server) noteOperation(ctx context.Context, name string) {
	s.policySnapshot()
	op, ok := s.operations[name]
	operationAudit(ctx, name, op.permission, ok)
}

func (s *Server) policyAllows(p Permission) bool {
	policy := s.policySnapshot()
	switch p {
	case ReadOnly:
		return true
	case RootTerminal:
		return policy.AllowRootTerminal
	case RootFiles:
		return policy.AllowRootFiles
	default:
		target, ok := strings.CutPrefix(string(p), "service:")
		return ok && validServiceTarget(target) && policy.serviceAllowed(target)
	}
}

// policySnapshot freezes host policy and the registry catalog. Both are
// startup-only; calling it from every entry point makes the first call
// authoritative and keeps dispatch and HTTP audit classification on one catalog.
func (s *Server) policySnapshot() Policy {
	s.policyOnce.Do(func() {
		s.policy = newPolicySnapshot(s.Policy)
		if s.Registry != nil {
			s.operations = s.Registry.snapshot()
		}
	})
	return s.policy
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	res, err := s.dispatch(r.Context(), "system.info", nil, s.requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	// GET /v1/info returns the info document directly; only operation calls
	// use the {"result": ...} envelope (spec §6.1).
	writeJSON(w, http.StatusOK, res)
}

// maxOpBodyBytes bounds the whole request envelope, not just params.
func parseOpEnvelope(w http.ResponseWriter, r *http.Request) (Params, error) {
	limited := http.MaxBytesReader(w, r.Body, maxOpBodyBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, newOpError(ErrPayloadTooLarge, "request body too large", nil)
		}
		return nil, invalidParams(map[string]string{"body": "unreadable request body"})
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, invalidParams(map[string]string{"body": "request body must be a single JSON object"})
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, decodeError(err)
	}
	var params Params
	seen := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, decodeError(err)
		}
		key, ok := tok.(string)
		if !ok || key != "params" {
			return nil, invalidParams(map[string]string{"body": "unknown field in request envelope"})
		}
		if seen {
			return nil, invalidParams(map[string]string{"body": "duplicate params field"})
		}
		seen = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, decodeError(err)
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' {
			return nil, invalidParams(map[string]string{"params": "params must be a JSON object"})
		}
		if !json.Valid(raw) {
			return nil, invalidParams(map[string]string{"params": "invalid JSON object"})
		}
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return nil, err
		}
		params = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, decodeError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalidParams(map[string]string{"body": "trailing data after JSON object"})
	}
	if !seen {
		return nil, invalidParams(map[string]string{"params": "params object is required"})
	}
	return params, nil
}

// rejectDuplicateJSONKeys walks tokens recursively, keeping a separate set of
// decoded key names for each object. Arrays recurse into each element, so keys
// repeated in distinct objects remain valid. UseNumber avoids float overflow
// while validating JSON that an operation may decode into a different type.
func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalidParams(map[string]string{"params": "trailing JSON data"})
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return decodeError(err)
	}
	delim, container := tok.(json.Delim)
	if !container {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return decodeError(err)
			}
			key, ok := tok.(string)
			if !ok || seen[key] {
				return invalidParams(map[string]string{"params": "duplicate JSON object key"})
			}
			seen[key] = true
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
	default:
		return invalidParams(map[string]string{"params": "unexpected JSON delimiter"})
	}
	if _, err := dec.Token(); err != nil {
		return decodeError(err)
	}
	return nil
}

func (s *Server) handleOp(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.noteOperation(r.Context(), name)
	params, err := parseOpEnvelope(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	res, err := s.dispatch(ctx, name, params, s.requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}

// writeError renders a protocol error. Internal failures never echo handler
// text or details: they may contain host paths or secrets. Only 500 is
// rewritten; every other code keeps its HTTPStatus mapping (400, 403, 404,
// 409, 413, 422, 429, 501, ...).
func writeError(w http.ResponseWriter, err error) {
	var oe *OpError
	if !errors.As(err, &oe) {
		oe = newOpError(ErrInternal, "unexpected failure", nil)
	}
	status := oe.HTTPStatus()
	if oe.Code == ErrInternal || status == http.StatusInternalServerError {
		oe = newOpError(ErrInternal, "unexpected failure", nil)
		status = http.StatusInternalServerError
	}
	if aw, ok := w.(*auditResponse); ok {
		aw.setErrorCode(oe.Code)
	}
	env := errorEnvelope{}
	env.set(oe)
	writeJSON(w, status, env)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		if aw, ok := w.(*auditResponse); ok {
			aw.setErrorCode(ErrInternal)
		}
		buf = []byte(`{"error":{"code":"internal","message":"unexpected failure"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(buf, '\n'))
}
