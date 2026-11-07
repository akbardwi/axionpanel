package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Params is the raw JSON object supplied by the caller for a single operation.
// Each operation decodes it into its own struct with unknown fields rejected,
// so parameters are validated per operation instead of being a free-form map.
type Params = json.RawMessage

// RequestMeta carries audit context. It is never transport authentication.
type RequestMeta struct {
	RequestID string
	Actor     string
	PeerUID   uint32
	Remote    bool
}

// Operation is a single member of the closed agent registry. There is
// deliberately no generic exec operation.
type Operation func(ctx context.Context, params Params, meta RequestMeta) (any, error)

var opNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$`)

// Registry maps operation names to handlers. Servers snapshot the catalog at
// initialization; later registrations affect only future servers. Registration
// and lookups are safe for concurrent use.
type Registry struct {
	mu  sync.RWMutex
	ops map[string]registeredOperation
}

type Permission string

const (
	ReadOnly     Permission = "read_only"
	RootTerminal Permission = "root_terminal"
	RootFiles    Permission = "root_files"
	StaticSites  Permission = "static_sites"
)

// Service binds a future operation to one exact startup-selected service.
// Request parameters never select or broaden this permission.
func Service(target string) Permission { return Permission("service:" + target) }

func (p Permission) valid() bool {
	if p == ReadOnly || p == RootTerminal || p == RootFiles || p == StaticSites {
		return true
	}
	target, ok := strings.CutPrefix(string(p), "service:")
	return ok && validServiceTarget(target)
}

func validServiceTarget(target string) bool {
	if len(target) == 0 || len(target) > 64 || !((target[0] >= 'a' && target[0] <= 'z') || (target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= '0' && target[0] <= '9')) {
		return false
	}
	for _, c := range target {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '@' || c == ':' || c == '#' {
			continue
		}
		return false
	}
	return true
}

type registeredOperation struct {
	handler     Operation
	permission  Permission
	builtinInfo bool
}

func NewRegistry() *Registry {
	return &Registry{ops: make(map[string]registeredOperation)}
}

// Register adds an operation. Duplicate and malformed names panic because both
// are programming errors discovered at startup, never request-driven.
func (r *Registry) Register(name string, op Operation, permissions ...Permission) {
	r.register(name, op, false, permissions...)
}

func (r *Registry) register(name string, op Operation, builtinInfo bool, permissions ...Permission) {
	permission := Permission("")
	if len(permissions) > 1 {
		panic("agent: multiple permissions")
	}
	if len(permissions) == 1 {
		permission = permissions[0]
		if !permission.valid() {
			panic("agent: unknown permission")
		}
	}
	if !opNamePattern.MatchString(name) {
		panic("agent: malformed operation name " + name)
	}
	if op == nil {
		panic("agent: nil operation " + name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.ops[name]; dup {
		panic("agent: duplicate operation " + name)
	}
	r.ops[name] = registeredOperation{handler: op, permission: permission, builtinInfo: builtinInfo}
}

func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.ops[name]
	return ok
}

// Names returns the registered catalog, sorted for stable reporting.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.ops))
	for n := range r.ops {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// snapshot returns an immutable copy of the catalog. A server takes exactly one
// during initialization, so registration after Handler/dispatch cannot widen a
// live server's permissions or exchange a handler.
func (r *Registry) snapshot() map[string]registeredOperation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]registeredOperation, len(r.ops))
	names := make([]string, 0, len(r.ops))
	for name, op := range r.ops {
		out[name] = op
		names = append(names, name)
	}
	sortStrings(names)
	for name, op := range out {
		if op.builtinInfo {
			op.handler = systemInfoForCatalog(names)
			out[name] = op
		}
	}
	return out
}

// lookup never executes handlers. All execution lives in Server.dispatch.
func (r *Registry) lookup(name string) (registeredOperation, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	op, ok := r.ops[name]
	return op, ok
}

// Run preserves the read-only embedding API, using the same canonical server
// dispatch with deny-by-default host policy. It cannot authorize root access.
func (r *Registry) Run(ctx context.Context, name string, params Params, meta RequestMeta) (any, error) {
	return (&Server{Registry: r}).dispatch(ctx, name, params, meta)
}

// decodeParams decodes an operation's parameters, rejecting unknown fields and
// trailing data so a caller cannot smuggle extra input past validation.
func decodeParams(raw Params, dst any) error {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 {
		data = []byte("{}")
	}
	if data[0] != '{' {
		return invalidParams(map[string]string{"params": "params must be a JSON object"})
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if dec.More() {
		return invalidParams(map[string]string{"body": "trailing data after JSON object"})
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalidParams(map[string]string{"body": "trailing data after JSON object"})
	}
	return nil
}

var unknownFieldPattern = regexp.MustCompile(`unknown field "([^"]+)"`)

func decodeError(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return newOpError(ErrPayloadTooLarge, "request body too large", nil)
	}
	if m := unknownFieldPattern.FindStringSubmatch(err.Error()); m != nil {
		return invalidParams(map[string]string{"unknown_field": m[1]})
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return invalidParams(map[string]string{"body": fmt.Sprintf("invalid JSON at offset %d", syntax.Offset)})
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return invalidParams(map[string]string{"body": "truncated JSON"})
	}
	return invalidParams(map[string]string{"body": "invalid parameter type"})
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
