-- authx initial schema
-- All timestamps are stored as timestamptz (UTC).
-- UUIDs are stored as uuid type (native Postgres).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_users (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email          TEXT        NOT NULL UNIQUE,
    email_verified BOOLEAN     NOT NULL DEFAULT false,
    metadata       JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_users_email_idx ON authx_users (email);

-- ── Sessions ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    device_info JSONB       NOT NULL DEFAULT '{}',
    ip_address  TEXT        NOT NULL DEFAULT '',
    org_id      UUID,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_sessions_user_id_idx    ON authx_sessions (user_id);
CREATE INDEX IF NOT EXISTS authx_sessions_token_hash_idx ON authx_sessions (token_hash);
CREATE INDEX IF NOT EXISTS authx_sessions_expires_at_idx ON authx_sessions (expires_at);

-- ── Credentials ───────────────────────────────────────────────────────────────

CREATE TYPE IF NOT EXISTS authx_credential_kind AS ENUM (
    'password',
    'passkey',
    'oauth_token'
);

CREATE TABLE IF NOT EXISTS authx_credentials (
    id              UUID                   PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID                   NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    kind            authx_credential_kind  NOT NULL,
    credential_hash TEXT                   NOT NULL,
    metadata        JSONB                  NOT NULL DEFAULT '{}',
    UNIQUE (user_id, kind)
);

CREATE INDEX IF NOT EXISTS authx_credentials_user_id_idx ON authx_credentials (user_id);

-- ── Organizations ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_orgs (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    slug       TEXT        NOT NULL UNIQUE,
    metadata   JSONB       NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_orgs_slug_idx ON authx_orgs (slug);

-- ── Roles ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_roles (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID    NOT NULL REFERENCES authx_orgs(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    permissions TEXT[]  NOT NULL DEFAULT '{}',
    UNIQUE (org_id, name)
);

-- ── Memberships ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_memberships (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES authx_users(id)    ON DELETE CASCADE,
    org_id     UUID        NOT NULL REFERENCES authx_orgs(id)     ON DELETE CASCADE,
    role_id    UUID        NOT NULL REFERENCES authx_roles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, org_id)
);

CREATE INDEX IF NOT EXISTS authx_memberships_org_id_idx  ON authx_memberships (org_id);
CREATE INDEX IF NOT EXISTS authx_memberships_user_id_idx ON authx_memberships (user_id);

-- ── Audit Logs ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS authx_audit_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        REFERENCES authx_users(id) ON DELETE SET NULL,
    org_id        UUID        REFERENCES authx_orgs(id)  ON DELETE SET NULL,
    action        TEXT        NOT NULL,
    resource_type TEXT        NOT NULL,
    resource_id   TEXT,
    ip_address    TEXT        NOT NULL DEFAULT '',
    metadata      JSONB       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_audit_logs_user_id_idx    ON authx_audit_logs (user_id);
CREATE INDEX IF NOT EXISTS authx_audit_logs_org_id_idx     ON authx_audit_logs (org_id);
CREATE INDEX IF NOT EXISTS authx_audit_logs_action_idx     ON authx_audit_logs (action);
CREATE INDEX IF NOT EXISTS authx_audit_logs_created_at_idx ON authx_audit_logs (created_at DESC);
