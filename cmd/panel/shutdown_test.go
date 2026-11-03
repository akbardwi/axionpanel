//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the real entry point, not a test HTTP server: signal handling,
// ListenAndServe/Shutdown ordering, embedded UI, and process exit all matter.
func TestPanelShutdown(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "panel")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/panel")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual panel: %v\n%s", err, output)
	}

	for _, signal := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		t.Run(signal.String(), func(t *testing.T) {
			panel := startShutdownPanel(t, binary)
			panel.signal(t, signal)
			panel.waitCleanExit(t)
		})
	}

	t.Run("SIGTERM drains partial request body", func(t *testing.T) {
		panel := startShutdownPanel(t, binary)
		conn, err := net.DialTimeout("tcp", panel.addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		body := `{"username":"","password":""}`
		// A 100 Continue response proves the actual handler has started reading
		// this body. No sleeps or guessed handler timing are needed.
		_, err = fmt.Fprintf(conn, "POST /api/v1/auth/login HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", panel.addr, panel.origin, len(body))
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		request := &http.Request{Method: http.MethodPost}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatalf("waiting for active body reader: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusContinue {
			t.Fatalf("before shutdown status = %d, want 100 Continue", response.StatusCode)
		}
		if _, err := io.WriteString(conn, body[:1]); err != nil {
			t.Fatal(err)
		}

		panel.signal(t, syscall.SIGTERM)
		panel.waitListenerClosed(t)
		select {
		case <-panel.done:
			t.Fatalf("panel exited before active request completed: %v\n%s", panel.exitErr, panel.logs())
		default:
		}
		if _, err := io.WriteString(conn, body[1:]); err != nil {
			t.Fatalf("complete body during shutdown: %v", err)
		}
		response, err = http.ReadResponse(reader, request)
		if err != nil {
			t.Fatalf("active request lost during shutdown: %v\n%s", err, panel.logs())
		}
		defer response.Body.Close()
		var result struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatalf("decode drained response: %v", err)
		}
		if response.StatusCode != http.StatusBadRequest || result.Error.Code != "invalid_request" {
			t.Fatalf("drained response = %d %#v, want normal validation response", response.StatusCode, result)
		}
		panel.waitCleanExit(t)
	})
}

type shutdownPanel struct {
	cmd     *exec.Cmd
	addr    string
	origin  string
	logPath string
	done    chan struct{}
	exitErr error // Written before done closes; read only after receiving done.
}

func startShutdownPanel(t *testing.T, binary string) *shutdownPanel {
	t.Helper()
	// Reserve an OS-selected loopback port. The executable currently accepts
	// only -addr, so release it immediately before starting the child.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	logPath := filepath.Join(private, "panel.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	origin := "http://" + addr
	cmd := exec.Command(binary,
		"-addr", addr,
		"-db", filepath.Join(private, "panel.db"),
		"-secret-key", filepath.Join(private, "secret.key"),
		"-agent-socket", filepath.Join(private, "absent-agent.sock"),
		"-origin", origin, "-insecure-loopback")
	cmd.Dir = private
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	panel := &shutdownPanel{cmd: cmd, addr: addr, origin: origin, logPath: logPath, done: make(chan struct{})}
	go func() {
		panel.exitErr = cmd.Wait()
		close(panel.done)
	}()
	t.Cleanup(func() {
		select {
		case <-panel.done:
		default:
			_ = cmd.Process.Kill()
			<-panel.done
		}
		if t.Failed() {
			t.Logf("panel output:\n%s", panel.logs())
		}
	})

	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-panel.done:
			t.Fatalf("panel exited before readiness: %v\n%s", panel.exitErr, panel.logs())
		default:
		}
		response, err := client.Get(origin + "/api/health")
		if err == nil {
			var health struct {
				Status string `json:"status"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || decodeErr != nil || health.Status != "ok" {
				t.Fatalf("health response = %d %+v, decode error %v", response.StatusCode, health, decodeErr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("panel did not become healthy: %v\n%s", err, panel.logs())
		}
		time.Sleep(20 * time.Millisecond)
	}
	response, err := client.Get(origin + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read embedded UI: %v", err)
	}
	// A clean checkout tracks only web/dist/.gitkeep, so the panel builds and
	// serves the documented "UI build missing" response until make web runs.
	// Both are valid here; only a crash or a dangling server is a failure.
	switch response.StatusCode {
	case http.StatusOK:
		if !strings.Contains(strings.ToLower(string(body)), "<!doctype html>") {
			t.Fatalf("embedded UI = %d, body %.200s", response.StatusCode, body)
		}
	case http.StatusServiceUnavailable:
		if !strings.Contains(string(body), "UI build missing") {
			t.Fatalf("missing build response = %d, body %.200s", response.StatusCode, body)
		}
	default:
		t.Fatalf("embedded UI = %d, body %.200s", response.StatusCode, body)
	}
	return panel
}

func (p *shutdownPanel) logs() string {
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

func (p *shutdownPanel) signal(t *testing.T, signal os.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(signal); err != nil {
		t.Fatalf("send %s: %v\n%s", signal, err, p.logs())
	}
}

func (p *shutdownPanel) waitListenerClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", p.addr, 100*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("listener still accepts connections after SIGTERM\n%s", p.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *shutdownPanel) waitCleanExit(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		if p.exitErr != nil {
			t.Fatalf("shutdown exit = %v, want exit status 0\n%s", p.exitErr, p.logs())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("panel did not exit within shutdown deadline\n%s", p.logs())
	}
}
