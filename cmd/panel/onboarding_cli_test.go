package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnboardingCLIEntranceInitAndPrivateBootstrap(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entrance := filepath.Join(dir, "entrance")
	out, stderr, err := runTransportPanel(t, binary, dir, "-init-entrance", "-entrance-file", entrance)
	if err != nil {
		t.Fatalf("entrance init failed: %v %s", err, stderr)
	}
	raw, err := os.ReadFile(entrance)
	if err != nil || validateBootstrapEntrance(string(raw)) != nil {
		t.Fatal("invalid generated entrance")
	}
	if strings.Contains(out+stderr, string(raw)) {
		t.Fatal("entrance leaked in output")
	}
	info, _ := os.Stat(entrance)
	if info.Mode().Perm() != 0600 {
		t.Fatal("entrance not private")
	}
	assertNoPanelState(t, dir)
	_, _, err = runTransportPanel(t, binary, dir, "-init-entrance", "-entrance-file", entrance)
	if err == nil {
		t.Fatal("init clobbered existing entrance")
	}
	after, _ := os.ReadFile(entrance)
	if string(after) != string(raw) {
		t.Fatal("existing entrance changed")
	}
	output := filepath.Join(dir, "bootstrap.json")
	out, stderr, err = runTransportPanel(t, binary, dir, "-bootstrap-admin", "admin", "-bootstrap-out", output, "-entrance-file", entrance)
	if err != nil {
		t.Fatalf("private bootstrap failed: %v %s", err, stderr)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var artifact bootstrapArtifact
	if json.Unmarshal(data, &artifact) != nil || artifact.EntrancePath != string(raw) || artifact.Username != "admin" || len(artifact.Password) != 24 {
		t.Fatal("invalid bootstrap artifact")
	}
	if strings.Contains(out+stderr, artifact.Password) || strings.Contains(out+stderr, string(raw)) {
		t.Fatal("bootstrap leaked secret")
	}
	_, _, err = runTransportPanel(t, binary, dir, "-bootstrap-admin", "second", "-bootstrap-out", filepath.Join(dir, "second.json"), "-entrance-file", entrance)
	if err == nil {
		t.Fatal("second bootstrap succeeded")
	}
	if _, err = os.Stat(filepath.Join(dir, "second.json")); !os.IsNotExist(err) {
		t.Fatal("second artifact created")
	}
}

func TestOnboardingCLIInvalidFlagsLeaveNoState(t *testing.T) {
	binary := buildTransportPanel(t)
	cases := [][]string{
		{"-bootstrap-out", "credentials.json"},
		{"-bootstrap-admin", "admin", "-bootstrap-out", "credentials.json"},
		{"-init-entrance"},
		{"-init-entrance", "-entrance-file", "entrance", "-init-tls", "-tls-host", "127.0.0.1", "-tls-cert", "cert", "-tls-key", "key"},
		{"-init-entrance", "-entrance-file", "entrance", "-tls-host", "127.0.0.1"},
		{"-init-entrance", "-entrance-file", "entrance", "-tls-cert", "cert"},
		{"-init-entrance", "-entrance-file", "entrance", "-tls-key", "key"},
		{"-init-entrance", "-entrance-file", "entrance", "-bootstrap-admin", "admin"},
		{"-init-entrance", "-entrance-file", "entrance", "-bootstrap-admin", "admin", "-bootstrap-out", "credentials.json"},
		{"-init-entrance", "-entrance-file", "entrance", "-insecure-loopback"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			_, _, err := runTransportPanel(t, binary, dir, args...)
			if err == nil {
				t.Fatalf("invalid flags accepted: %v", args)
			}
			assertNoPanelState(t, dir)
			entries, readErr := os.ReadDir(dir)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("invalid flags created files: %v, %v", entries, readErr)
			}
		})
	}
}
