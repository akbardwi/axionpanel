# Durable panel security audit

`Writer.Append` accepts a closed action/outcome/factor vocabulary, verified actor
ID/name, validated IP and an optional unverified candidate username. It accepts
no request bodies, headers, error text, passwords, tokens, factor values,
credential hashes or arbitrary details. Names are normalized to valid UTF-8,
control characters replaced, and bounded to 128 bytes. Unknown login names live
only in JSON `candidate_username` with `candidate_verified: false`; `user_id`
and the verified username column remain NULL. SQL parameters and JSON encoding
are used throughout. This does not make a submitted candidate a trusted actor.

Auth derives actors from validated auth state and IPs through its existing
trusted-proxy resolver. Account changes target the actor's own numeric user ID.
The writer accepts a `*sql.Tx` so callers can persist event and state atomically;
an insert that affects zero rows is also an error. Migration 00003 adds a DELETE
guard without changing migration 00001's immutable-field UPDATE guard. Its Down
removes only the DELETE guard. `store.Open` enables `recursive_triggers(1)` via
the `modernc.org/sqlite` driver's `_pragma` DSN parameters on **every pooled
connection**, including connections opened later. That makes both `REPLACE` and
`INSERT OR REPLACE` fire the DELETE guard and abort before erasing old rows,
including conflicts addressed through `id`, `rowid`, `oid` or `_rowid_`.
There is no BEFORE INSERT ID lookup: SQLite leaves `NEW.rowid` undefined when an
automatic ID is requested, so that lookup can confuse it with a valid explicit
negative ID such as `-1` and block normal appends. Explicit negative IDs remain
valid, and later `Writer.Append` calls can allocate IDs normally. User deletion
still nulls the foreign key while retaining the actor name snapshot.

Replacement protection requires connections from `store.Open` and
`recursive_triggers` left enabled; arbitrary external SQLite connections must
set the same pragma. Disabling it bypasses replacement protection (but not
direct DELETE or immutable-field UPDATE guards). This is application/database
append-only protection, not tamper evidence against a database administrator
who can change pragmas, drop triggers or modify the database file.

### Guard regression checks

`go test ./internal/audit ./internal/store -count=1` covers migration Down/Up,
immutable fields, FK user deletion, automatic appends with an explicit `-1`
(both negative-only and positive-maximum histories), and replacement rejection
through all four ID aliases for negative, zero, positive and int64-boundary IDs.
The pool test holds four connections simultaneously, checks both required
pragmas on each, then repeats with four fresh connections. Every failed
replacement must preserve the original row and history count. Scoped race and
vet checks: `go test -race ./internal/audit ./internal/store -count=1` and
`go vet ./internal/audit ./internal/store`.

## Actual coverage

| Action | Actual emission |
| --- | --- |
| `auth.login` | Non-MFA HTTP login success, password rejection, username/account lockout or IP-rate-limit denial |
| `auth.password.verify` | Successful direct `Service.Authenticate` password verification (not a completed MFA sign-in) |
| `auth.session.create` | Successful direct `Service.CreateSession` |
| `auth.mfa.challenge` | Password-verified MFA challenge creation, before intermediate cookie/CSRF is sent |
| `auth.login.mfa` | Completed MFA login, invalid/expired/exhausted existing challenge verdicts, per-user lockout and IP denial for an existing valid-CSRF challenge |
| `auth.logout` | Authenticated, CSRF-validated HTTP logout |
| `auth.reauth` | Successful sudo grant (password, TOTP or recovery factor); wrong password, password lockout/IP denial; missing/ambiguous second factor, factor-user lockout and wrong factor |
| `auth.mfa.setup` | Pending enrollment stored, before secret/otpauth URL is returned |
| `auth.mfa.enable` | Successful enrollment, rejected enrollment code |
| `auth.recovery_codes.generate` | Initial code issuance during successful MFA enable |
| `auth.recovery_code.use` | Successful recovery use during login or sudo reauthentication |
| `auth.mfa.disable` | Successful disable and related revocations |
| `auth.password.change` | Successful `POST /api/v1/auth/password` with `{"new_password":"..."}`; requires CSRF and fresh sudo, atomically revokes all sessions and pending MFA challenges, clears cookies, and requires sign-in again |

Session creation, logout, password rotation, enrollment setup/enable/disable,
factor consumption and sudo grant share the event transaction. An audit insert
failure returns a generic 500, rolls those mutations back, and sends no newly
granted credential/secret/recovery codes. Database/commit failures are not
reported as auth success. As with any database commit error, a lost connection
or ambiguous commit acknowledgement can leave the caller uncertain whether the
transaction committed; no success credentials are sent on that path.

The existing pre-Argon2 failure reservation deliberately commits separately to
bound concurrent guesses and preserve throttle behavior. Password failures and
denials are durably audited after verification. If audit then fails, the HTTP
response is 500 but that conservative throttle reservation remains; it is not
refunded, and no session/sudo is granted. Sudo password verification likewise
resets/refunds its password counters before the later factor/grant transaction.
Its success audit is emitted only with the sudo grant, not at that intermediate
step. `last_login_at` for HTTP MFA login is now written only on full factor
completion, not when issuing a challenge.

## Explicit exclusions

No per-poll audit for GET `/auth/me`, telemetry or other safe reads. No audit read
API or UI. No blanket middleware logging: malformed JSON/length errors, origin or
CSRF rejection, missing/unknown challenge cookies, absent/expired auth sessions,
service-unavailable/internal errors, stale-session revalidation and setup/disable
precondition denials are not asserted to be audited. Account bootstrap/create,
direct `DeleteSession`, automatic expired-session cleanup and recovery-code
regeneration outside enrollment are not covered. No new regeneration endpoint
exists. Direct `Authenticate` still validates only the password; `CreateSession`
retains its existing password-only MFA semantics, and Lookup rejects an
unsatisfied MFA session. No production credentials, external services or network
requests are involved in tests.
