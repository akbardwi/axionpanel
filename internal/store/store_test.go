package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func openMigrated(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// seed inserts one valid row of each core entity. IDs are fixed so the
// constraint tests below can refer to them.
func seed(t *testing.T, db *sql.DB) {
	t.Helper()
	mustExec(t, db, `INSERT INTO users (id, username, password_hash) VALUES (1, 'admin', 'argon2id$x')`)
	mustExec(t, db, `INSERT INTO system_users (id, server_id, owner_user_id, username, uid, home_dir)
		VALUES (1, 1, 1, 'ap_example_com', 2001, '/var/www/example.com')`)
	mustExec(t, db, `INSERT INTO sites (id, server_id, owner_user_id, system_user_id, kind, root_dir, php_version)
		VALUES (1, 1, 1, 1, 'php', '/var/www/example.com/public', '8.3')`)
	mustExec(t, db, `INSERT INTO site_domains (site_id, domain, is_primary) VALUES (1, 'example.com', 1)`)
	mustExec(t, db, `INSERT INTO site_domains (site_id, domain) VALUES (1, 'www.example.com')`)
	mustExec(t, db, `INSERT INTO databases (id, server_id, owner_user_id, site_id, engine, name)
		VALUES (1, 1, 1, 1, 'mariadb', 'example')`)
	mustExec(t, db, `INSERT INTO database_users (id, server_id, owner_user_id, engine, username)
		VALUES (1, 1, 1, 'mariadb', 'example')`)
	mustExec(t, db, `INSERT INTO database_grants (database_id, database_user_id) VALUES (1, 1)`)
	mustExec(t, db, `INSERT INTO cron_jobs (server_id, owner_user_id, system_user_id, name, schedule, command)
		VALUES (1, 1, 1, 'wp-cron', '*/5 * * * *', 'php /var/www/example.com/public/wp-cron.php')`)
	mustExec(t, db, `INSERT INTO firewall_rules (server_id, action, protocol, port_from, is_system)
		VALUES (1, 'allow', 'tcp', 22, 1)`)
	mustExec(t, db, `INSERT INTO jobs (id, server_id, user_id, type, params)
		VALUES ('01JBTESTJOB0000000000000000', 1, 1, 'site.apply', '{"site_id":1}')`)
	mustExec(t, db, `INSERT INTO audit_log (user_id, username, action, outcome)
		VALUES (1, 'admin', 'site.create', 'success')`)
}

func TestOpenSetsPragmas(t *testing.T) {
	db := openMigrated(t)
	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d, %v; want 1", fk, err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v; want wal", mode, err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := openMigrated(t)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestSeedDataIsValid(t *testing.T) {
	db := openMigrated(t)
	seed(t, db)

	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported violations")
	}

	var local int
	if err := db.QueryRow(`SELECT count(*) FROM servers WHERE is_local = 1`).Scan(&local); err != nil || local != 1 {
		t.Fatalf("local servers = %d, %v; want 1", local, err)
	}
	var settings int
	if err := db.QueryRow(`SELECT count(*) FROM settings`).Scan(&settings); err != nil || settings == 0 {
		t.Fatalf("default settings = %d, %v; want > 0", settings, err)
	}
}

func TestConstraintsRejectInvalidRows(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"duplicate domain, different case", `INSERT INTO site_domains (site_id, domain) VALUES (1, 'EXAMPLE.com')`},
		{"second primary domain", `INSERT INTO site_domains (site_id, domain, is_primary) VALUES (1, 'other.com', 1)`},
		{"php site without php_version", `INSERT INTO sites (server_id, owner_user_id, system_user_id, kind, root_dir)
			VALUES (1, 1, 1, 'php', '/var/www/x')`},
		{"static site with php_version", `INSERT INTO sites (server_id, owner_user_id, system_user_id, kind, root_dir, php_version)
			VALUES (1, 1, 1, 'static', '/var/www/x', '8.3')`},
		{"proxy site without target", `INSERT INTO sites (server_id, owner_user_id, system_user_id, kind, root_dir)
			VALUES (1, 1, 1, 'proxy', '/var/www/x')`},
		{"unknown role", `INSERT INTO users (username, password_hash, role) VALUES ('bob', 'x', 'root')`},
		{"duplicate username, different case", `INSERT INTO users (username, password_hash) VALUES ('ADMIN', 'x')`},
		{"2FA enabled without secret", `INSERT INTO users (username, password_hash, totp_enabled) VALUES ('carol', 'x', 1)`},
		{"second local server", `INSERT INTO servers (name, hostname, is_local, agent_endpoint) VALUES ('b', 'b', 1, 'unix:///x')`},
		{"site on missing server", `INSERT INTO sites (server_id, owner_user_id, system_user_id, kind, root_dir)
			VALUES (99, 1, 1, 'static', '/var/www/x')`},
		{"cron command with newline", "INSERT INTO cron_jobs (server_id, owner_user_id, name, schedule, command)\n" +
			"VALUES (1, 1, 'x', '* * * * *', 'true' || char(10) || '* * * * * root evil')"},
		{"port out of range", `INSERT INTO firewall_rules (server_id, action, protocol, port_from) VALUES (1, 'allow', 'tcp', 70000)`},
		{"port range reversed", `INSERT INTO firewall_rules (server_id, action, protocol, port_from, port_to) VALUES (1, 'allow', 'tcp', 90, 80)`},
		{"invalid job params JSON", `INSERT INTO jobs (id, server_id, type, params) VALUES ('j2', 1, 'x', '{bad')`},
		{"api token scopes not an array", `INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes)
			VALUES (1, 't', 'axp_1234', 'h', '{}')`},
		{"STRICT type check", `INSERT INTO firewall_rules (server_id, action, protocol, port_from) VALUES (1, 'allow', 'tcp', 'ssh')`},
		{"delete user that owns a site", `DELETE FROM users WHERE id = 1`},
		{"edit audit entry", `UPDATE audit_log SET action = 'nothing.happened'`},
		{"reassign audit entry", `INSERT INTO users (id, username, password_hash) VALUES (5, 'mallory', 'x');
			UPDATE audit_log SET user_id = 5`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openMigrated(t)
			seed(t, db)
			if _, err := db.Exec(tc.query); err == nil {
				t.Fatalf("expected constraint failure, got none for:\n%s", tc.query)
			} else if testing.Verbose() {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

func TestDeletingUserKeepsAuditHistory(t *testing.T) {
	db := openMigrated(t)
	seed(t, db)
	mustExec(t, db, `INSERT INTO users (id, username, password_hash) VALUES (2, 'temp', 'x')`)
	mustExec(t, db, `INSERT INTO audit_log (user_id, username, action, outcome) VALUES (2, 'temp', 'auth.login', 'success')`)

	mustExec(t, db, `DELETE FROM users WHERE id = 2`)

	var userID sql.NullInt64
	var username string
	err := db.QueryRow(`SELECT user_id, username FROM audit_log WHERE action = 'auth.login'`).Scan(&userID, &username)
	if err != nil {
		t.Fatal(err)
	}
	if userID.Valid || username != "temp" {
		t.Fatalf("audit row = (%v, %q); want (NULL, \"temp\")", userID, username)
	}
}

func TestDeletingSiteCascadesDomains(t *testing.T) {
	db := openMigrated(t)
	seed(t, db)
	mustExec(t, db, `DELETE FROM sites WHERE id = 1`)

	var domains int
	if err := db.QueryRow(`SELECT count(*) FROM site_domains`).Scan(&domains); err != nil || domains != 0 {
		t.Fatalf("domains after site delete = %d, %v; want 0", domains, err)
	}
	var siteID sql.NullInt64
	if err := db.QueryRow(`SELECT site_id FROM databases WHERE id = 1`).Scan(&siteID); err != nil || siteID.Valid {
		t.Fatalf("database.site_id = %v, %v; want NULL", siteID, err)
	}
}

func TestDownRemovesSchema(t *testing.T) {
	db := openMigrated(t)
	m, err := newMigrator(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.DownTo(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var n int
	err = db.QueryRow(`SELECT count(*) FROM sqlite_master
		WHERE type IN ('table', 'trigger') AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version'`).Scan(&n)
	if err != nil || n != 0 {
		t.Fatalf("objects left after down = %d, %v; want 0", n, err)
	}
}
