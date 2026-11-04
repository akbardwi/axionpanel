package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSocketPolicyAndKernelAudit(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	var calls atomic.Int32
	unsafe := func(context.Context, Params, RequestMeta) (any, error) { calls.Add(1); return nil, nil }
	r.Register("test.unsafe", unsafe, RootTerminal)
	r.Register("test.unclassified", unsafe)
	logs := make(chan string, 16)
	s := &Server{Registry: r, Socket: filepath.Join(shortTempDir(t), "a.sock"), AllowedUID: uint32(os.Geteuid()), AllowRootPeer: true, Logger: func(f string, a ...any) { logs <- fmt.Sprintf(f, a...) }}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := s.Listen(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", s.Socket)
	}}
	cli := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	for _, tc := range []struct {
		path, method, op, class, outcome, code string
		status                                 int
	}{
		{"/v1/ops/test.unsafe", "POST", "test.unsafe", "root_terminal", "denied", ErrForbiddenByPolicy, 403},
		{"/v1/ops/test.unclassified", "POST", "test.unclassified", "unclassified", "denied", ErrForbiddenByPolicy, 403},
		{"/v1/ops/secret.unknown", "POST", "unknown", "unclassified", "denied", ErrNotFound, 404},
		{"/v1/info", "GET", "system.info", "read_only", "success", "", 200},
		{"/v1/ops/system.stats", "POST", "system.stats", "read_only", "success", "", 200},
		{"/v1/ops/system.metrics", "POST", "system.metrics", "read_only", "success", "", 200},
		{"/v1/ops/capabilities.refresh", "POST", "capabilities.refresh", "read_only", "success", "", 200},
	} {
		req, _ := http.NewRequest(tc.method, "http://unix"+tc.path, strings.NewReader(`{"params":{}}`))
		req.Header.Set("Axion-Protocol", "1")
		req.Header.Set("Axion-Actor", "7")
		req.Header.Set("Axion-Request-ID", "socket:1")
		res, err := cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s status=%d want=%d", tc.path, res.StatusCode, tc.status)
		}
		var line string
		select {
		case line = <-logs:
		case <-time.After(time.Second):
			t.Fatal("missing audit")
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["operation"] != tc.op || rec["classification"] != tc.class || rec["outcome"] != tc.outcome {
			t.Fatalf("%s record=%s", tc.path, line)
		}
		if uid, ok := rec["peer_uid"].(float64); !ok || uint32(uid) != uint32(os.Geteuid()) {
			t.Fatalf("not kernel uid: %s", line)
		}
		if rec["actor"] != "7" || rec["request_id"] != "socket:1" {
			t.Fatalf("lost validated context %s", line)
		}
		if tc.code != "" && rec["error_code"] != tc.code {
			t.Fatalf("wrong code %s", line)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe handler ran")
	}
}
