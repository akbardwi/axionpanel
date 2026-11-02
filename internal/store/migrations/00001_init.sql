-- AxionPanel initial schema, SQLite dialect. See docs/spec.md section 8.
-- Timestamps: TEXT, UTC ISO-8601. Booleans: INTEGER 0/1.
-- *_hash columns never hold raw secrets; *_enc columns hold AES-256-GCM ciphertext.

-- +goose Up
CREATE TABLE packages (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    max_sites     INTEGER,
    max_databases INTEGER,
    disk_quota_mb INTEGER,
    bandwidth_mb  INTEGER,
    cpu_percent   INTEGER,
    memory_mb     INTEGER,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email           TEXT,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'reseller', 'user')),
    parent_id       INTEGER REFERENCES users (id) ON DELETE RESTRICT,
    package_id      INTEGER REFERENCES packages (id) ON DELETE SET NULL,
    totp_secret_enc TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_login_at   TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    CHECK (totp_enabled = 0 OR totp_secret_enc IS NOT NULL)
) STRICT;

CREATE TABLE user_recovery_codes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (user_id, code_hash)
) STRICT;

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY,
    token_hash      TEXT    NOT NULL UNIQUE,
    csrf_token_hash TEXT    NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip              TEXT,
    user_agent      TEXT,
    mfa_passed      INTEGER NOT NULL DEFAULT 0 CHECK (mfa_passed IN (0, 1)),
    sudo_until      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at      TEXT    NOT NULL
) STRICT;
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    token_prefix TEXT    NOT NULL,
    token_hash   TEXT    NOT NULL UNIQUE,
    scopes       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    allowed_ips  TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_ips) AND json_type(allowed_ips) = 'array'),
    last_used_at TEXT,
    expires_at   TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (user_id, name)
) STRICT;

CREATE TABLE servers (
    id             INTEGER PRIMARY KEY,
    name           TEXT    NOT NULL UNIQUE,
    hostname       TEXT    NOT NULL,
    is_local       INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    agent_endpoint TEXT    NOT NULL,
    agent_version  TEXT,
    os_id          TEXT,
    os_version     TEXT,
    arch           TEXT,
    status         TEXT    NOT NULL DEFAULT 'unknown' CHECK (status IN ('online', 'offline', 'unknown')),
    last_seen_at   TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;
CREATE UNIQUE INDEX servers_one_local ON servers (is_local) WHERE is_local = 1;

CREATE TABLE system_users (
    id            INTEGER PRIMARY KEY,
    server_id     INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    owner_user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    username      TEXT    NOT NULL CHECK (length(username) BETWEEN 1 AND 32),
    uid           INTEGER NOT NULL,
    home_dir      TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (server_id, username),
    UNIQUE (server_id, uid)
) STRICT;

CREATE TABLE ssl_certificates (
    id                    INTEGER PRIMARY KEY,
    server_id             INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    provider              TEXT    NOT NULL CHECK (provider IN ('letsencrypt', 'zerossl', 'custom')),
    domains               TEXT    NOT NULL CHECK (json_valid(domains) AND json_type(domains) = 'array'),
    cert_path             TEXT    NOT NULL,
    key_path              TEXT    NOT NULL,
    issuer                TEXT,
    issued_at             TEXT,
    expires_at            TEXT,
    auto_renew            INTEGER NOT NULL DEFAULT 1 CHECK (auto_renew IN (0, 1)),
    last_renew_attempt_at TEXT,
    last_error            TEXT,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;
CREATE INDEX ssl_renewal_idx ON ssl_certificates (expires_at) WHERE auto_renew = 1;

CREATE TABLE sites (
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
CREATE INDEX sites_owner_idx ON sites (owner_user_id);
CREATE INDEX sites_server_idx ON sites (server_id);

CREATE TABLE site_domains (
    id         INTEGER PRIMARY KEY,
    site_id    INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    domain     TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(domain) BETWEEN 3 AND 253),
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;
CREATE INDEX site_domains_site_idx ON site_domains (site_id);
CREATE UNIQUE INDEX site_domains_one_primary ON site_domains (site_id) WHERE is_primary = 1;

CREATE TABLE databases (
    id             INTEGER PRIMARY KEY,
    server_id      INTEGER NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    owner_user_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    site_id        INTEGER REFERENCES sites (id) ON DELETE SET NULL,
    engine         TEXT    NOT NULL CHECK (engine IN ('mariadb', 'mysql', 'postgresql')),
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 32),
    charset        TEXT    NOT NULL DEFAULT 'utf8mb4',
    collation_name TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (server_id, engine, name)
) STRICT;
CREATE INDEX databases_owner_idx ON databases (owner_user_id);

CREATE TABLE database_users (
    id            INTEGER PRIMARY KEY,
    server_id     INTEGER NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    owner_user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    engine        TEXT    NOT NULL CHECK (engine IN ('mariadb', 'mysql', 'postgresql')),
    username      TEXT    NOT NULL CHECK (length(username) BETWEEN 1 AND 32),
    host          TEXT    NOT NULL DEFAULT 'localhost',
    password_enc  TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (server_id, engine, username, host)
) STRICT;

CREATE TABLE database_grants (
    database_id      INTEGER NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    database_user_id INTEGER NOT NULL REFERENCES database_users (id) ON DELETE CASCADE,
    privileges       TEXT    NOT NULL DEFAULT 'ALL',
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (database_id, database_user_id)
) STRICT;

CREATE TABLE cron_jobs (
    id             INTEGER PRIMARY KEY,
    server_id      INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    owner_user_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    system_user_id INTEGER REFERENCES system_users (id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    schedule       TEXT    NOT NULL,
    command        TEXT    NOT NULL CHECK (instr(command, char(10)) = 0 AND instr(command, char(13)) = 0),
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_run_at    TEXT,
    last_exit_code INTEGER,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

CREATE TABLE firewall_rules (
    id         INTEGER PRIMARY KEY,
    server_id  INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    action     TEXT    NOT NULL CHECK (action IN ('allow', 'deny')),
    protocol   TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp', 'both')),
    port_from  INTEGER NOT NULL CHECK (port_from BETWEEN 1 AND 65535),
    port_to    INTEGER CHECK (port_to IS NULL OR (port_to >= port_from AND port_to <= 65535)),
    source     TEXT,
    comment    TEXT    NOT NULL DEFAULT '',
    is_system  INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

CREATE TABLE jobs (
    id          TEXT    PRIMARY KEY,
    server_id   INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    type        TEXT    NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    status      TEXT    NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    progress    INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    params      TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
    result      TEXT    CHECK (result IS NULL OR json_valid(result)),
    error       TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    started_at  TEXT,
    finished_at TEXT
) STRICT;
CREATE INDEX jobs_status_idx ON jobs (status, created_at);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    username    TEXT,
    ip          TEXT,
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    details     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
    outcome     TEXT    NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;
CREATE INDEX audit_log_created_idx ON audit_log (created_at);
CREATE INDEX audit_log_user_idx ON audit_log (user_id);

-- Audit rows are append-only. Only user_id may change, and only to NULL,
-- which is what ON DELETE SET NULL does when a user is deleted.
-- +goose StatementBegin
CREATE TRIGGER audit_log_append_only
BEFORE UPDATE ON audit_log
WHEN NEW.id IS NOT OLD.id
  OR NEW.username IS NOT OLD.username
  OR NEW.ip IS NOT OLD.ip
  OR NEW.action IS NOT OLD.action
  OR NEW.target_type IS NOT OLD.target_type
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.details IS NOT OLD.details
  OR NEW.outcome IS NOT OLD.outcome
  OR NEW.created_at IS NOT OLD.created_at
  OR (NEW.user_id IS NOT OLD.user_id AND NEW.user_id IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

INSERT INTO servers (id, name, hostname, is_local, agent_endpoint)
VALUES (1, 'local', 'localhost', 1, 'unix:///run/axionpanel/agent.sock');

INSERT INTO settings (key, value) VALUES
    ('security.session_idle_minutes', '120'),
    ('security.session_absolute_hours', '24'),
    ('security.sudo_minutes', '10'),
    ('security.login_max_failures', '5'),
    ('security.ip_allowlist', '[]');

-- +goose Down
DROP TABLE settings;
DROP TRIGGER audit_log_append_only;
DROP TABLE audit_log;
DROP TABLE jobs;
DROP TABLE firewall_rules;
DROP TABLE cron_jobs;
DROP TABLE database_grants;
DROP TABLE database_users;
DROP TABLE databases;
DROP TABLE site_domains;
DROP TABLE sites;
DROP TABLE ssl_certificates;
DROP TABLE system_users;
DROP TABLE servers;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE user_recovery_codes;
DROP TABLE users;
DROP TABLE packages;
