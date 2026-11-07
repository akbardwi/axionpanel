-- Static-only sites: the site row stays authoritative, but a static site has
-- no site OS user (initial content is root-owned, docs/static-sites-plan.md).
-- Rebuild the table in place because SQLite cannot drop NOT NULL. Child tables
-- keep their foreign keys: the table is never renamed, only dropped after the
-- replacement exists, and the whole change runs under deferred FK checks.
-- +goose Up
PRAGMA defer_foreign_keys = ON;

CREATE TABLE sites_new (
    id                 INTEGER PRIMARY KEY,
    server_id          INTEGER NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    owner_user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    system_user_id     INTEGER REFERENCES system_users (id) ON DELETE RESTRICT,
    kind               TEXT    NOT NULL CHECK (kind IN ('php', 'static', 'proxy')),
    root_dir           TEXT    NOT NULL,
    php_version        TEXT,
    proxy_target       TEXT,
    ssl_certificate_id INTEGER REFERENCES ssl_certificates (id) ON DELETE SET NULL,
    force_https        INTEGER NOT NULL DEFAULT 0 CHECK (force_https IN (0, 1)),
    custom_directives  TEXT    NOT NULL DEFAULT '',
    static_listen      TEXT,
    status             TEXT    NOT NULL DEFAULT 'provisioning'
        CHECK (status IN ('provisioning', 'active', 'suspended', 'error', 'deleting', 'deleted')),
    last_error         TEXT,
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CHECK ((kind = 'php') = (php_version IS NOT NULL)),
    CHECK ((kind = 'proxy') = (proxy_target IS NOT NULL)),
    CHECK (kind = 'static' OR system_user_id IS NOT NULL),
    CHECK (static_listen IS NULL OR length(static_listen) BETWEEN 1 AND 255)
) STRICT;

INSERT INTO sites_new (id, server_id, owner_user_id, system_user_id, kind, root_dir,
    php_version, proxy_target, ssl_certificate_id, force_https, custom_directives,
    status, last_error, created_at, updated_at)
SELECT id, server_id, owner_user_id, system_user_id, kind, root_dir,
    php_version, proxy_target, ssl_certificate_id, force_https, custom_directives,
    status, last_error, created_at, updated_at
FROM sites;

-- DROP invokes existing ON DELETE actions even with deferred checks. Save
-- and restore the two child relationships explicitly in the same transaction.
CREATE TEMP TABLE static_domain_backup AS SELECT * FROM site_domains;
CREATE TEMP TABLE static_database_backup AS SELECT id, site_id FROM databases;
DROP TABLE sites;
ALTER TABLE sites_new RENAME TO sites;
INSERT INTO site_domains SELECT * FROM static_domain_backup;
UPDATE databases SET site_id=(SELECT site_id FROM static_database_backup b WHERE b.id=databases.id);
DROP TABLE static_domain_backup;
DROP TABLE static_database_backup;

CREATE INDEX sites_owner_idx ON sites (owner_user_id);
CREATE INDEX sites_server_idx ON sites (server_id);

-- +goose Down
PRAGMA defer_foreign_keys = ON;

CREATE TABLE sites_old (
    id                 INTEGER PRIMARY KEY,
    server_id          INTEGER NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    owner_user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    system_user_id     INTEGER NOT NULL REFERENCES system_users (id) ON DELETE RESTRICT,
    kind               TEXT    NOT NULL CHECK (kind IN ('php', 'static', 'proxy')),
    root_dir           TEXT    NOT NULL,
    php_version        TEXT,
    proxy_target       TEXT,
    ssl_certificate_id INTEGER REFERENCES ssl_certificates (id) ON DELETE SET NULL,
    force_https        INTEGER NOT NULL DEFAULT 0 CHECK (force_https IN (0, 1)),
    custom_directives  TEXT    NOT NULL DEFAULT '',
    status             TEXT    NOT NULL DEFAULT 'provisioning'
        CHECK (status IN ('provisioning', 'active', 'suspended', 'error', 'deleting')),
    last_error         TEXT,
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CHECK ((kind = 'php') = (php_version IS NOT NULL)),
    CHECK ((kind = 'proxy') = (proxy_target IS NOT NULL))
) STRICT;

-- Fails loudly rather than dropping data when a static (system_user_id NULL)
-- or tombstoned ('deleted') row cannot be represented by the old schema.
INSERT INTO sites_old (id, server_id, owner_user_id, system_user_id, kind, root_dir,
    php_version, proxy_target, ssl_certificate_id, force_https, custom_directives,
    status, last_error, created_at, updated_at)
SELECT id, server_id, owner_user_id, system_user_id, kind, root_dir,
    php_version, proxy_target, ssl_certificate_id, force_https, custom_directives,
    status, last_error, created_at, updated_at
FROM sites;

CREATE TEMP TABLE static_domain_backup AS SELECT * FROM site_domains;
CREATE TEMP TABLE static_database_backup AS SELECT id, site_id FROM databases;
DROP TABLE sites;
ALTER TABLE sites_old RENAME TO sites;
INSERT INTO site_domains SELECT * FROM static_domain_backup;
UPDATE databases SET site_id=(SELECT site_id FROM static_database_backup b WHERE b.id=databases.id);
DROP TABLE static_domain_backup;
DROP TABLE static_database_backup;

CREATE INDEX sites_owner_idx ON sites (owner_user_id);
CREATE INDEX sites_server_idx ON sites (server_id);
