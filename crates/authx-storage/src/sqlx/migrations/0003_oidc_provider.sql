-- authx acts as Identity Provider (IdP) and OAuth2 authorization server.

-- OIDC clients (registered applications that use authx for auth)
CREATE TABLE IF NOT EXISTS authx_oidc_clients (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id      TEXT        NOT NULL UNIQUE,
    secret_hash    TEXT        NOT NULL DEFAULT '',
    name           TEXT        NOT NULL,
    redirect_uris  TEXT[]      NOT NULL DEFAULT '{}',
    grant_types    TEXT[]      NOT NULL DEFAULT '{}',
    response_types TEXT[]      NOT NULL DEFAULT '{}',
    allowed_scopes TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_oidc_clients_client_id_idx ON authx_oidc_clients (client_id);

-- Authorization codes (authorization_code grant)
CREATE TABLE IF NOT EXISTS authx_oidc_authorization_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash       TEXT        NOT NULL UNIQUE,
    client_id       TEXT        NOT NULL,
    user_id         UUID        NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    redirect_uri    TEXT        NOT NULL,
    scope           TEXT        NOT NULL DEFAULT '',
    nonce           TEXT,
    code_challenge  TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_oidc_auth_codes_code_hash_idx ON authx_oidc_authorization_codes (code_hash);
CREATE INDEX IF NOT EXISTS authx_oidc_auth_codes_expires_idx   ON authx_oidc_authorization_codes (expires_at);

-- OIDC tokens (access, refresh)
CREATE TABLE IF NOT EXISTS authx_oidc_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  TEXT        NOT NULL UNIQUE,
    client_id   TEXT        NOT NULL,
    user_id     UUID        NOT NULL REFERENCES authx_users(id) ON DELETE CASCADE,
    scope       TEXT        NOT NULL DEFAULT '',
    token_type  TEXT        NOT NULL, -- 'access', 'refresh', 'device_access'
    expires_at  TIMESTAMPTZ,
    revoked    BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_oidc_tokens_token_hash_idx ON authx_oidc_tokens (token_hash);
CREATE INDEX IF NOT EXISTS authx_oidc_tokens_client_user_idx ON authx_oidc_tokens (client_id, user_id);

-- OIDC Federation providers (external IdPs: Okta, Azure AD, Google Workspace)
CREATE TABLE IF NOT EXISTS authx_oidc_federation_providers (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    issuer      TEXT        NOT NULL,
    client_id   TEXT        NOT NULL,
    secret_enc  TEXT        NOT NULL,
    scopes      TEXT        NOT NULL DEFAULT 'openid profile email',
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_oidc_fed_providers_name_idx ON authx_oidc_federation_providers (name);

-- Device authorization codes (RFC 8628 — Device Authorization Grant)
CREATE TABLE IF NOT EXISTS authx_device_codes (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash  TEXT        NOT NULL UNIQUE,
    user_code_hash    TEXT        NOT NULL UNIQUE,
    user_code         TEXT        NOT NULL,
    client_id         TEXT        NOT NULL,
    scope             TEXT        NOT NULL DEFAULT '',
    expires_at        TIMESTAMPTZ NOT NULL,
    interval_secs     INTEGER     NOT NULL DEFAULT 5,
    authorized        BOOLEAN     NOT NULL DEFAULT false,
    denied            BOOLEAN     NOT NULL DEFAULT false,
    user_id           UUID        REFERENCES authx_users(id) ON DELETE SET NULL,
    last_polled_at    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS authx_device_codes_device_hash_idx    ON authx_device_codes (device_code_hash);
CREATE INDEX IF NOT EXISTS authx_device_codes_user_code_hash_idx ON authx_device_codes (user_code_hash);
CREATE INDEX IF NOT EXISTS authx_device_codes_expires_idx        ON authx_device_codes (expires_at);
CREATE INDEX IF NOT EXISTS authx_device_codes_client_idx         ON authx_device_codes (client_id);
