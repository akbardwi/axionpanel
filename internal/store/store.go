// Package store owns the panel database: connection setup and schema migrations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/url"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// connectionPragmas are applied through the DSN so that every pooled
// connection gets them, not just the first one.
var connectionPragmas = []string{
	"foreign_keys(1)",
	"journal_mode(WAL)",
	"busy_timeout(5000)",
	"synchronous(NORMAL)",
}

// Open opens the SQLite database at path with the pragmas the panel relies on.
func Open(path string) (*sql.DB, error) {
	q := url.Values{}
	for _, p := range connectionPragmas {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}

func newMigrator(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectSQLite3, db, sub)
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, db *sql.DB) error {
	m, err := newMigrator(db)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if _, err := m.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
