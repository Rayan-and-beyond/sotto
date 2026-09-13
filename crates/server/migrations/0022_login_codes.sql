-- Single-use login codes for the CLI loopback flow.
--
-- The OAuth callback used to hand the CLI its 30-day session token in the redirect URL, which
-- put it in the Caddy access log (reproduced) and in browser history. The callback now hands
-- back a short-lived, single-use code instead, and the CLI exchanges it for the session in
-- a POST body. Only the code's BLAKE2b hash is stored, so a database leak cannot be replayed.
--
-- `oauth_logins.wants_code` records whether the CLI asked for the code branch (`mode=code` at
-- login); its absence means a legacy CLI that still expects the token in the URL.
-- `sessions.via_legacy_cli` marks sessions issued through that legacy branch, so its remaining
-- use is one query away when planning removal.

CREATE TABLE IF NOT EXISTS cli_login_codes (
    code_hash  BYTEA PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    cli_state  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- The code branch sweeps expired rows on every callback; index the sweep like 0013 does for
-- oauth_logins, so a flood of abandoned codes stays cheap instead of re-scanning the table.
CREATE INDEX IF NOT EXISTS cli_login_codes_expires_at_idx ON cli_login_codes (expires_at);

ALTER TABLE oauth_logins ADD COLUMN IF NOT EXISTS wants_code BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS via_legacy_cli BOOLEAN NOT NULL DEFAULT FALSE;
