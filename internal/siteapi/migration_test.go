package siteapi

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"axionpanel/internal/store"
	"github.com/pressly/goose/v3"
)

// migrateTo applies only the migrations up to version, so a populated
// pre-static schema can be upgraded by the production migration under test.
func migrateTo(t *testing.T, db *sql.DB, version int64) {
	t.Helper()
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("../store/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	migrateTo(t, db, 3)
	return db
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestMigrationPreservesPopulatedSites(t *testing.T) {
	db := openDB(t)
	exec(t, db, `INSERT INTO users(id,username,password_hash) VALUES(1,'admin','x')`)
	exec(t, db, `INSERT INTO system_users(id,server_id,owner_user_id,username,uid,home_dir)
		VALUES(1,1,1,'ap_example_com',2001,'/var/www/example.com')`)
	exec(t, db, `INSERT INTO sites(id,server_id,owner_user_id,system_user_id,kind,root_dir,php_version)
		VALUES(1,1,1,1,'php','/var/www/example.com/public','8.3')`)
	exec(t, db, `INSERT INTO sites(id,server_id,owner_user_id,system_user_id,kind,root_dir)
		VALUES(2,1,1,1,'static','/var/www/static.example.com')`)
	exec(t, db, `INSERT INTO site_domains(site_id,domain,is_primary) VALUES(1,'example.com',1)`)
	exec(t, db, `INSERT INTO site_domains(site_id,domain,is_primary) VALUES(2,'static.example.com',1)`)
	exec(t, db, `INSERT INTO databases(server_id,owner_user_id,site_id,engine,name) VALUES(1,1,1,'mariadb','example')`)

	migrateTo(t, db, 4)

	var kind, php string
	var systemUser sql.NullInt64
	if err := db.QueryRow(`SELECT kind,COALESCE(php_version,''),system_user_id FROM sites WHERE id=1`).
		Scan(&kind, &php, &systemUser); err != nil {
		t.Fatal(err)
	}
	if kind != "php" || php != "8.3" || !systemUser.Valid {
		t.Fatalf("php site changed: %q %q %v", kind, php, systemUser)
	}
	var domains int
	if err := db.QueryRow(`SELECT count(*) FROM site_domains`).Scan(&domains); err != nil || domains != 2 {
		t.Fatalf("domains = %d, %v; want 2", domains, err)
	}
	var dbSite int64
	if err := db.QueryRow(`SELECT COALESCE(site_id,0) FROM databases`).Scan(&dbSite); err != nil || dbSite != 1 {
		t.Fatalf("database site_id = %d, %v; want 1", dbSite, err)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("foreign_key_check reported violations after rebuild")
	}
	rows.Close()

	// The new shape: static sites carry no OS user, php sites still must.
	exec(t, db, `INSERT INTO sites(server_id,owner_user_id,kind,root_dir) VALUES(1,1,'static','/var/www/a.example')`)
	exec(t, db, `INSERT INTO sites(server_id,owner_user_id,kind,root_dir,status,static_listen)
		VALUES(1,1,'static','/var/www/b.example','deleted','127.0.0.1:8080')`)
	if _, err := db.Exec(`INSERT INTO sites(server_id,owner_user_id,kind,root_dir,php_version)
		VALUES(1,1,'static','/var/www/c.example','8.3')`); err == nil {
		t.Fatal("static site accepted a php_version")
	}
	if _, err := db.Exec(`INSERT INTO sites(server_id,owner_user_id,system_user_id,kind,root_dir)
		VALUES(1,1,1,'php','/var/www/d.example')`); err == nil {
		t.Fatal("php site without php_version accepted")
	}
	if _, err := db.Exec(`INSERT INTO sites(server_id,owner_user_id,kind,root_dir)
		VALUES(1,1,'proxy','/var/www/e.example')`); err == nil {
		t.Fatal("proxy site without target accepted")
	}
}

func TestMigrationDownRefusesUnrepresentableRows(t *testing.T) {
	db := openDB(t)
	exec(t, db, `INSERT INTO users(id,username,password_hash) VALUES(1,'admin','x')`)
	migrateTo(t, db, 4)
	exec(t, db, `INSERT INTO sites(server_id,owner_user_id,kind,root_dir) VALUES(1,1,'static','/var/www/a.example')`)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("../store/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(context.Background(), 3); err == nil {
		t.Fatal("down migration discarded a static site without an OS user")
	}
}
