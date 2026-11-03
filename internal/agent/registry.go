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

// Registry maps operation names to handlers. Registration happens at startup
// only; lookups are safe for concurrent use.
type Registry struct {
	mu  sync.RWMutex
	ops map[string]Operation
}

func NewRegistry() *Registry {
	return &Registry{ops: make(map[string]Operation)}
}

// Register adds an operation. Duplicate and malformed names panic because both
// are programming errors discovered at startup, never request-driven.
func (r *Registry) Register(name string, op Operation) {
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
	r.ops[name] = op
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

// Run dispatches to a registered operation. Anything absent from the registry
// is not_found, which also covers attempts at path or shell injection.
func (r *Registry) Run(ctx context.Context, name string, params Params, meta RequestMeta) (result any, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = newOpError(ErrInternal, "unexpected failure", nil)
		}
	}()
	r.mu.RLock()
	op, ok := r.ops[name]
	r.mu.RUnlock()
	if !ok {
		return nil, newOpError(ErrNotFound, "operation is not in the agent catalog", map[string]string{"operation": name})
	}
	return op(ctx, params, meta)
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
