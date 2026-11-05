package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOnboardingServingGate(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entrance := filepath.Join(dir, "entrance")
	if err := os.WriteFile(entrance, []byte(bootstrapTestEntrance), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "server.log")
	logfile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logfile.Close()
	cmd := exec.Command(binary, "-addr", "127.0.0.1:0", "-origin", "http://localhost:7800", "-insecure-loopback", "-entrance-file", entrance)
	cmd.Dir = dir
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		if m := regexPortZero.FindSubmatch(data); m != nil {
			addr = string(m[1])
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start")
	}
	base := "http://" + addr
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 2 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	check := func(path string, want int) *http.Response {
		t.Helper()
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s status=%d want=%d", path, resp.StatusCode, want)
		}
		return resp
	}
	for _, p := range []string{"/api/health", "/login", "/api/v1/auth/me", "/assets/app.js"} {
		check(p, 404)
	}
	resp := check(bootstrapTestEntrance, 303)
	if resp.Header.Get("Location") != "/login" {
		t.Fatal("unexpected redirect")
	}
	check("/api/health", 200)
	check("/api/v1/auth/me", 401)
}
