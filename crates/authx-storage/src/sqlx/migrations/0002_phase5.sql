-- Phase 5 schema additions

-- Add username to users
ALTER TABLE authx_users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;

-- API keys
CREATE TABLE IF NOT EXISTS authx_api_keys (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    org_id       UUID        REFERENCES authx_orgs(id) ON DELETE SET NULL,
    key_hash     TEXT        NOT NULL UNIQUE,
    prefix       TEXT        NOT NULL,
    name         TEXT        NOT NULL,
    scopes       TEXT[]      NOT NULL DEFAULT '{}',
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth accounts
CREATE TABLE IF NOT EXISTS authx_oauth_accounts (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    provider          TEXT        NOT NULL,
    provider_user_id  TEXT        NOT NULL,
    access_token_enc  TEXT        NOT NULL,
    refresh_token_enc TEXT,
    expires_at        TIMESTAMPTZ,
    UNIQUE (provider, provider_user_id)
);

-- Org invites
CREATE TABLE IF NOT EXISTS authx_invites (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES authx_orgs(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    role_id     UUID        NOT NULL REFERENCES authx_roles(id),
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS authx_api_keys_user_id_idx  ON authx_api_keys  (user_id);
CREATE INDEX IF NOT EXISTS authx_oauth_accounts_user_id_idx ON authx_oauth_accounts (user_id);
CREATE INDEX IF NOT EXISTS authx_invites_org_id_idx    ON authx_invites    (org_id);
