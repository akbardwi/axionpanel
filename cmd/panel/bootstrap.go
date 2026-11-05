// Package main implements the AxionPanel operator CLI.
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"axionpanel/internal/auth"
)

type bootstrapArtifact struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	EntrancePath string `json:"entrance_path"`
	Origin       string `json:"origin"`
}

// bootstrapToFile creates a private first-administrator artifact. It creates
// no network listener and never exposes the generated password through logs.
func bootstrapToFile(ctx context.Context, db *sql.DB, username, outputPath, entrancePath, origin string) error {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 {
		return fmt.Errorf("panel: invalid bootstrap username")
	}
	if err := validateBootstrapEntrance(entrancePath); err != nil {
		return err
	}
	cfg := auth.DefaultConfig()
	cfg.Origin = origin
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("panel: invalid bootstrap origin: %w", err)
	}
	password, err := auth.NewPassword()
	if err != nil {
		return fmt.Errorf("panel: generate bootstrap password: %w", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("panel: hash bootstrap password: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("panel: begin bootstrap transaction: %w", err)
	}
	defer tx.Rollback() // No-op after Commit, including an ambiguous Commit error.
	if _, err = tx.ExecContext(ctx, `UPDATE users SET id=id WHERE 0`); err != nil {
		return fmt.Errorf("panel: acquire bootstrap lock: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("panel: inspect bootstrap state: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("panel: bootstrap unavailable: administrator already exists")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(username,password_hash,role) VALUES(?,?,?)`, username, hash, "admin"); err != nil {
		return fmt.Errorf("panel: create bootstrap administrator: %w", err)
	}

	artifact, err := buildBootstrapArtifact(username, password, entrancePath, origin)
	if err != nil {
		return err
	}
	if err := writeBootstrapArtifact(outputPath, artifact); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		// Preserve the artifact for local recovery because the commit may have
		// succeeded after the client error.
		return fmt.Errorf("panel: commit bootstrap transaction: %w", err)
	}
	return nil
}

func buildBootstrapArtifact(username, password, entrancePath, origin string) ([]byte, error) {
	payload, err := json.Marshal(bootstrapArtifact{Username: username, Password: password, EntrancePath: entrancePath, Origin: origin})
	if err != nil {
		return nil, fmt.Errorf("panel: encode bootstrap artifact: %w", err)
	}
	return payload, nil
}

func writeBootstrapArtifact(path string, payload []byte) error {
	if err := ensureBootstrapOutputParent(path); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("panel: bootstrap output parent is unavailable")
	}
	defer root.Close()
	// Recheck the opened directory, not just its pathname, so a renamed
	// parent cannot redirect creation into a directory with unsafe access.
	parent, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("panel: bootstrap output parent is unavailable")
	}
	if err := validateBootstrapDirectoryInfo(parent); err != nil {
		return err
	}
	name := filepath.Base(path)
	if name == "" {
		return fmt.Errorf("panel: bootstrap output must be a file name")
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("panel: bootstrap output cannot be created")
	}
	created, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("panel: bootstrap output cannot be verified")
	}
	if !created.Mode().IsRegular() {
		f.Close()
		removeOwnedBootstrapArtifact(root, name, created)
		return fmt.Errorf("panel: bootstrap output is not a regular file")
	}
	if err := writeAndCloseBootstrapArtifact(f, payload); err != nil {
		removeOwnedBootstrapArtifact(root, name, created)
		return err
	}
	return nil
}

func removeOwnedBootstrapArtifact(root *os.Root, name string, owned os.FileInfo) {
	current, err := root.Lstat(name)
	if err == nil && os.SameFile(current, owned) {
		_ = root.Remove(name)
	}
}

// writeAndCloseBootstrapArtifact writes and durably closes a newly opened
// owner-only artifact. The path is retained only on an ambiguous commit
// failure; earlier write/sync/close errors remove the file again.
type bootstrapArtifactFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func writeAndCloseBootstrapArtifact(f bootstrapArtifactFile, payload []byte) error {
	if n, err := f.Write(payload); err != nil || n != len(payload) {
		f.Close()
		return fmt.Errorf("panel: bootstrap artifact write failed")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("panel: bootstrap artifact sync failed")
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("panel: bootstrap artifact close failed")
	}
	return nil
}

func ensureBootstrapOutputParent(path string) error {
	if path == "" {
		return fmt.Errorf("panel: bootstrap output is required")
	}
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return fmt.Errorf("panel: bootstrap output must be a regular file")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("panel: bootstrap output path is unavailable")
	}
	parent := filepath.Dir(abs)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("panel: bootstrap output parent is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("panel: bootstrap output parent must not be a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("panel: bootstrap output parent must be a directory")
	}
	if err := validateBootstrapDirectoryInfo(info); err != nil {
		return err
	}
	return nil
}

func validateBootstrapDirectoryInfo(info os.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&0o077 != 0 || perm&0o300 != 0o300 {
		return fmt.Errorf("panel: bootstrap output parent must be owner-only and writable")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("panel: bootstrap output owner cannot be verified")
	}
	if int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("panel: bootstrap output must be owned by the panel user")
	}
	return nil
}

func validateBootstrapEntrance(path string) error {
	if path == "" || len(path) != 13 || path[0] != '/' {
		return fmt.Errorf("panel: invalid entrance path")
	}
	body := path[1:]
	for _, r := range body {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
			return fmt.Errorf("panel: invalid entrance path")
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(body); err != nil {
		return fmt.Errorf("panel: invalid entrance path")
	}
	return nil
}
