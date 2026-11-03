package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/agent"
)

func TestRunRequiresExplicitNonRootIdentity(t *testing.T) {
	for _, args := range [][]string{nil, {"--allow-uid", "1000"}, {"--socket-gid", "1000"}, {"--allow-uid", "0", "--socket-gid", "1000"}, {"--allow-uid", "root", "--socket-gid", "1000"}, {"--allow-uid", "1000", "--socket-gid", "0"}, {"--allow-uid", "1000", "--socket-gid", "1000", "extra"}, {"--allow-uid", "1000", "--socket-gid", "1000", "--listen", "127.0.0.1:0"}} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := run(ctx, args); err == nil || errors.Is(err, context.Canceled) {
			t.Errorf("invalid args accepted: %v error=%v", args, err)
		}
	}
}

// Cancellation before the listener exists is the only case that reports
// context.Canceled: Listen refuses to create the endpoint.
func TestRunPreServeCancellationReturnsContextCanceled(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "run", "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := run(ctx, []string{"--allow-uid", "1000", "--socket-gid", "1000", "--policy", "", "--socket", sock})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled run created socket: %v", err)
	}
}

// A signal during Serve is a clean stop: run returns nil (so main exits 0) and
// the socket is removed. It must not surface context.Canceled as a failure.
func TestRunCleanShutdownOnSignalReturnsNil(t *testing.T) {
	gid := os.Getegid()
	if gid == 0 {
		gid = 1000
	}
	if os.Geteuid() != 0 && gid != os.Getegid() {
		t.Skip("needs root to chown the socket directory")
	}
	sock := filepath.Join(t.TempDir(), "run", "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"--allow-uid", "1000", "--socket-gid", strconv.Itoa(gid), "--policy", "", "--socket", sock})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent never published its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("signal shutdown reported error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed on stop: %v", err)
	}
}

// Startup errors from the agent package already carry the "agent: " prefix;
// main must not add a second one ("agent: agent: ...").
func TestStartupMessageHasSinglePrefix(t *testing.T) {
	for _, in := range []string{"agent: insecure socket directory", "agent policy: cannot open", "--allow-uid is required"} {
		msg := startupMessage(errors.New(in))
		if strings.Contains(msg, "agent: agent:") {
			t.Errorf("%q doubled the prefix: %q", in, msg)
		}
		if !strings.HasPrefix(msg, "agent: ") {
			t.Errorf("%q missing prefix: %q", in, msg)
		}
		if strings.Count(msg, "agent: ") != 1 {
			t.Errorf("%q prefix count != 1: %q", in, msg)
		}
	}
	if got, want := startupMessage(errors.New("agent: insecure socket directory")), "agent: insecure socket directory"; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
}

func TestResolveGroupName(t *testing.T) {
	group, err := user.LookupGroupId("1")
	if err != nil {
		t.Skip(err)
	}
	got, err := resolveGID(group.Name)
	if err != nil || got != 1 {
		t.Fatalf("gid=%d err=%v", got, err)
	}
}

func TestRunVersionNeedsNoPrivilegesOrConfig(t *testing.T) {
	if err := run(context.Background(), []string{"--version"}); err != nil {
		t.Fatal(err)
	}
}

// Makefile stamps -X main.version; the stamp must reach both --version and
// the agent package (which serves /v1/info).
func TestLinkerVersionStampReachesCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip(err)
	}
	bin := filepath.Join(t.TempDir(), "agent")
	build := exec.Command(goBin, "build", "-ldflags", "-X main.version=9.9.9-stamp", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "9.9.9-stamp" {
		t.Fatalf("--version = %q, want stamped version", got)
	}
}

func TestRunPublishesStampedVersionToAgent(t *testing.T) {
	oldMain, oldAgent := version, agent.Version
	defer func() { version, agent.Version = oldMain, oldAgent }()
	version = "7.7.7-test"
	if err := run(context.Background(), []string{"--version"}); err != nil {
		t.Fatal(err)
	}
	if agent.Version != "7.7.7-test" {
		t.Fatalf("agent.Version = %q", agent.Version)
	}
}
