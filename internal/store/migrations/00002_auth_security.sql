-- Auth hardening: pending TOTP enrollment, TOTP replay protection, persistent
-- MFA login challenges and failure throttling. See docs/spec.md section 5.1.
-- *_hash columns never hold raw secrets; *_enc columns hold AES-256-GCM ciphertext.

-- +goose Up
-- Enrollment secret awaiting confirmation; kept apart from the active secret
-- so an abandoned setup never changes how the account signs in.
ALTER TABLE users ADD COLUMN totp_pending_secret_enc TEXT;
-- Highest TOTP time step accepted so far; codes at or below it are replays.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;

-- Password-verified logins waiting for the second factor. Single use: a row
-- is deleted when the challenge succeeds, expires or runs out of attempts.
CREATE TABLE mfa_challenges (
    id              INTEGER PRIMARY KEY,
    token_hash      TEXT    NOT NULL UNIQUE,
    csrf_token_hash TEXT    NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip              TEXT,
    user_agent      TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at      TEXT    NOT NULL
) STRICT;
CREATE INDEX mfa_challenges_user_idx ON mfa_challenges (user_id);
CREATE INDEX mfa_challenges_expires_idx ON mfa_challenges (expires_at);

-- Fixed-window failure counters: per client IP (or IPv6 /64), per unknown
-- username, and per user for second-factor failures.
CREATE TABLE auth_throttle (
    scope        TEXT    NOT NULL CHECK (scope IN ('ip', 'username', 'mfa_user')),
    key          TEXT    NOT NULL,
    failures     INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    window_start TEXT    NOT NULL,
    locked_until TEXT,
    PRIMARY KEY (scope, key)
) STRICT;
CREATE INDEX auth_throttle_window_idx ON auth_throttle (window_start);

-- +goose Down
DROP TABLE auth_throttle;
DROP TABLE mfa_challenges;
ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN totp_pending_secret_enc;
