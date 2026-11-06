//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axionpanel/internal/paneltls"
)

func TestTLSInitRejectsOtherActionsBeforeWrites(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, extra := range [][]string{
		{"-bootstrap-admin", "admin"},
		{"-entrance-file", "entrance"},
		{"-insecure-loopback"},
	} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"-init-tls", "-tls-host", "127.0.0.1", "-tls-cert", "cert", "-tls-key", "key"}, extra...)
			_, stderr, err := runTransportPanel(t, binary, dir, args...)
			if err == nil || !strings.Contains(stderr, "cannot be combined") {
				t.Fatalf("expected explicit mixed-mode refusal: err=%v stderr=%s", err, stderr)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("mixed-mode refusal left files: %v err=%v", entries, err)
			}
		})
	}
}

func TestTLSBootstrapDoesNotValidateUnusedBind(t *testing.T) {
	binary := buildTransportPanel(t)
	material := t.TempDir()
	cert, key := filepath.Join(material, "cert"), filepath.Join(material, "key")
	if _, err := paneltls.Init(cert, key, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"127.0.0.1:7800", "invalid", "192.0.2.123:8443"} {
		t.Run(addr, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			entrance := filepath.Join(dir, "entrance")
			if err := initEntranceFile(entrance); err != nil {
				t.Fatal(err)
			}
			outFile := filepath.Join(dir, "bootstrap.json")
			_, stderr, err := runTransportPanel(t, binary, dir,
				"-addr", addr, "-origin", "https://panel.example.com",
				"-tls-cert", cert, "-tls-key", key,
				"-bootstrap-admin", "admin", "-bootstrap-out", outFile,
				"-entrance-file", entrance)
			if err != nil {
				t.Fatalf("non-binding bootstrap rejected unused bind: %v stderr=%s", err, stderr)
			}
			if info, err := os.Stat(outFile); err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private bootstrap artifact missing or unsafe")
			}
		})
	}
}
