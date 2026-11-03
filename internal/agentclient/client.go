// Package agentclient is the panel's HTTP client for the local agent daemon.
// It speaks the closed protocol over a Unix socket and never accepts an
// unbounded, unvalidated response: bodies are size-limited and the protocol
// version in the response must match ours.
package agentclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const (
	protocol         = 1
	maxResponseBytes = 1 << 20 // 1 MiB, mirrors the agent's request limit
	defaultTimeout   = 10 * time.Second
	dialTimeout      = 2 * time.Second
)

// Sentinel errors the panel maps to its own error surface.
var (
	// ErrUnavailable means the agent could not be reached or a transport read
	// failed. An HTTP body ending before its declared length is instead invalid.
	ErrUnavailable = errors.New("agent unavailable")
	// ErrProtocol means the agent answered with a different protocol version
	// or omitted the protocol header.
	ErrProtocol = errors.New("agent protocol mismatch")
	// ErrInvalidResponse means the agent returned a body this client refuses
	// to parse (oversized or malformed).
	ErrInvalidResponse = errors.New("agent returned an invalid response")
	// ErrInvalidRequest means the caller built a request this client refuses
	// to send (for example a malformed operation name).
	ErrInvalidRequest = errors.New("invalid agent request")
)

// Error is an error reported by the agent in the protocol envelope. Code and
// Status come straight from the agent; the panel decides how much to surface.
type Error struct {
	Code    string
	Message string
	Status  int
	Details json.RawMessage
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "agent: " + e.Code
	}
	return "agent: " + e.Code + ": " + e.Message
}

// Info is the document the agent serves at GET /v1/info.
type Info struct {
	Version            string                `json:"version"`
	Protocol           int                   `json:"protocol"`
	OS                 string                `json:"os"`
	Arch               string                `json:"arch"`
	Kernel             string                `json:"kernel"`
	Hostname           string                `json:"hostname"`
	DetectedTools      map[string]bool       `json:"detected_tools"`
	Capabilities       map[string]Capability `json:"capabilities"`
	CapabilityRevision string                `json:"capability_revision"`
	ObservedAt         string                `json:"observed_at"`
	Operations         []string              `json:"operations"`
}

// Capability is one managed-feature claim from the agent.
type Capability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// Stats is the live host metrics document from system.stats.
type Stats struct {
	Load1             float64 `json:"load1"`
	Load5             float64 `json:"load5"`
	Load15            float64 `json:"load15"`
	MemTotalBytes     uint64  `json:"mem_total_bytes"`
	MemAvailableBytes uint64  `json:"mem_available_bytes"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
	ObservedAt        string  `json:"observed_at"`
}

// Capabilities is the result of capabilities.refresh.
type Capabilities struct {
	DetectedTools      map[string]bool       `json:"detected_tools"`
	Capabilities       map[string]Capability `json:"capabilities"`
	CapabilityRevision string                `json:"capability_revision"`
	ObservedAt         string                `json:"observed_at"`
}

var opNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$`)

// Client talks to one local agent socket. It is safe for concurrent use.
type Client struct {
	socket string
	http   *http.Transport
	// Timeout bounds the whole request, including the dial.
	Timeout time.Duration
}

type actorKey struct{}

// WithActor attributes an agent request to an authenticated panel user.
// A missing or non-positive ID is rejected before dialing. This is audit
// metadata, never a substitute for the agent's SO_PEERCRED authorization.
func WithActor(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, actorKey{}, id)
}

// New returns a client for the given Unix socket path with safe defaults.
func New(socket string) *Client {
	c := &Client{socket: socket, Timeout: defaultTimeout}
	c.http = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 0, // bounded by http.Client.Timeout below
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
	}
	return c
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

// Info fetches and validates the agent info document.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	var out Info
	if err := c.get(ctx, "/v1/info", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stats runs the read-only system.stats operation.
func (c *Client) Stats(ctx context.Context) (*Stats, error) {
	var out Stats
	if err := c.Call(ctx, "system.stats", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RefreshCapabilities runs the read-only capabilities.refresh operation.
func (c *Client) RefreshCapabilities(ctx context.Context) (*Capabilities, error) {
	var out Capabilities
	if err := c.Call(ctx, "capabilities.refresh", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// get runs a GET for a raw document. Only /v1/info is raw in the protocol;
// every operation goes through Call and its result envelope.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := c.setHeaders(req); err != nil {
		return err
	}
	res, err := c.do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := checkProtocol(res); err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(res)
	}
	return decodeBody(res, out)
}

// do sends the request. http.Client.Timeout covers dial, headers and the
// whole body read, so callers may read the body after do returns; a
// per-call context cancelled on return would abort that read.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	client := &http.Client{
		Transport: c.http,
		Timeout:   c.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return res, nil
}

func (c *Client) setHeaders(req *http.Request) error {
	id, _ := req.Context().Value(actorKey{}).(int64)
	if id <= 0 {
		return fmt.Errorf("%w: positive panel user ID required", ErrInvalidRequest)
	}
	req.Header.Set("Axion-Protocol", strconv.Itoa(protocol))
	req.Header.Set("Axion-Request-ID", newRequestID())
	req.Header.Set("Axion-Actor", strconv.FormatInt(id, 10))
	return nil
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "req-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

func checkProtocol(res *http.Response) error {
	vals := res.Header.Values("Axion-Protocol")
	if len(vals) != 1 || vals[0] != strconv.Itoa(protocol) {
		return fmt.Errorf("%w: got %q", ErrProtocol, vals)
	}
	return nil
}

func decodeBody(res *http.Response, out any) error {
	limited := io.LimitReader(res.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: truncated body: %v", ErrInvalidResponse, err)
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidResponse, maxResponseBytes)
	}
	return decodeDocument(body, out)
}

// requiredObject distinguishes missing and null fields from legitimate zero
// values. Unknown fields remain compatible with additions to protocol 1.
func requiredObject(body []byte, fields ...string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return fmt.Errorf("%w: expected JSON object", ErrInvalidResponse)
	}
	for _, field := range fields {
		raw, ok := obj[field]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%w: missing or null %s", ErrInvalidResponse, field)
		}
	}
	return nil
}

func decodeDocument(body []byte, out any) error {
	if _, ok := out.(*Info); ok {
		if err := requiredObject(body, "version", "protocol", "os", "arch", "kernel", "hostname",
			"detected_tools", "capabilities", "capability_revision", "observed_at", "operations"); err != nil {
			return err
		}
	}
	if _, ok := out.(*Stats); ok {
		if err := requiredObject(body, "load1", "load5", "load15", "mem_total_bytes",
			"mem_available_bytes", "uptime_seconds", "observed_at"); err != nil {
			return err
		}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if st, ok := out.(*Stats); ok {
		for _, value := range []float64{st.Load1, st.Load5, st.Load15, st.UptimeSeconds} {
			if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("%w: invalid stats value", ErrInvalidResponse)
			}
		}
		if st.MemTotalBytes == 0 || st.MemAvailableBytes > st.MemTotalBytes {
			return fmt.Errorf("%w: invalid memory bounds", ErrInvalidResponse)
		}
		if _, err := time.Parse(time.RFC3339, st.ObservedAt); err != nil {
			return fmt.Errorf("%w: invalid observed_at", ErrInvalidResponse)
		}
	}
	if info, ok := out.(*Info); ok {
		if info.Protocol != protocol {
			return fmt.Errorf("%w: info protocol %d", ErrInvalidResponse, info.Protocol)
		}
		if _, err := time.Parse(time.RFC3339, info.ObservedAt); err != nil {
			return fmt.Errorf("%w: invalid observed_at", ErrInvalidResponse)
		}
	}
	return nil
}

// Call posts a closed-protocol operation and unwraps the {"result": ...}
// envelope. The operation name is validated client-side so a programming
// error cannot produce a malformed request path.
func (c *Client) Call(ctx context.Context, op string, params any, out any) error {
	if !opNamePattern.MatchString(op) {
		return fmt.Errorf("%w: invalid operation name %q", ErrInvalidRequest, op)
	}
	if params == nil {
		params = struct{}{}
	}
	payload, err := json.Marshal(map[string]any{"params": params})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/ops/"+op, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := c.setHeaders(req); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := checkProtocol(res); err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(res)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := decodeBody(res, &env); err != nil {
		return err
	}
	if err := requiredObject(env.Result); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return decodeDocument(env.Result, out)
}

func decodeError(res *http.Response) error {
	var env struct {
		Error json.RawMessage `json:"error"`
	}
	if err := decodeBody(res, &env); err != nil {
		return err
	}
	if err := requiredObject(env.Error, "code", "message"); err != nil {
		return err
	}
	var detail struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(env.Error, &detail); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if detail.Code == "" {
		return fmt.Errorf("%w: empty error code", ErrInvalidResponse)
	}
	return &Error{
		Code:    detail.Code,
		Message: detail.Message,
		Status:  res.StatusCode,
		Details: detail.Details,
	}
}
