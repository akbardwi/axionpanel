-- Audit log hardening: rows are append-only for every role. The user_id
-- foreign key still nulls actor links when a user is deleted; that is an
-- UPDATE performed by SQLite, which the original update guard permits.
-- store.Open enables recursive_triggers on EVERY connection so this DELETE
-- guard also refuses REPLACE's implicit deletion. Do not disable that pragma.
-- No BEFORE INSERT rowid check: NEW.rowid is undefined for automatic IDs there.
-- +goose Up
-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_delete;
