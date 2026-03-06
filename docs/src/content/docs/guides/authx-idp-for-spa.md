---
title: Use authx-rs as an IdP for Your SPA
description: Register a browser client, run authorization code with PKCE, and use authx-rs as your SPA's OpenID Connect provider.
---

This guide covers the case where authx-rs is the identity provider and your SPA is the client application.

## Recommended shape

- authx-rs runs as the OIDC provider
- your SPA is a public client
- use authorization code with PKCE
- use authx sessions for the provider's own login UI
- use OIDC tokens for the SPA's relationship with the provider

## 1. Register the SPA as an OIDC client

Create an OIDC client with:

- a redirect URI owned by the SPA, such as `https://app.example.com/auth/callback`
- `authorization_code` in `grant_types`
- `code` in `response_types`
- no client secret for a public SPA client
- scopes such as `openid profile email`

## 2. Mount the provider router

```rust
use std::sync::Arc;

use authx_axum::{oidc_provider_router, OidcProviderState};
use authx_core::KeyRotationStore;
use authx_plugins::oidc_provider::{OidcProviderConfig, OidcProviderService};

let key_store = KeyRotationStore::new(3);
key_store.add_key("v1", PRIV_PEM, PUB_PEM)?;

let config = OidcProviderConfig {
    issuer: "https://auth.example.com".into(),
    key_store,
    access_token_ttl_secs: 3600,
    id_token_ttl_secs: 3600,
    refresh_token_ttl_secs: 60 * 60 * 24 * 30,
    auth_code_ttl_secs: 600,
    device_code_ttl_secs: 600,
    device_code_interval_secs: 5,
    verification_uri: "https://auth.example.com/oidc/device".into(),
};

let service = Arc::new(OidcProviderService::new(store.clone(), config.clone()));

let oidc = oidc_provider_router(OidcProviderState {
    service,
    config,
    issuer: "https://auth.example.com".into(),
    base_path: "/oidc".into(),
    public_pem: PUB_PEM.to_vec(),
    jwks_kid: "v1".into(),
});
```

## 3. Send the browser to `/authorize`

Your SPA generates PKCE values and redirects the browser to:

```text
https://auth.example.com/oidc/authorize
  ?client_id=...
  &redirect_uri=https://app.example.com/auth/callback
  &response_type=code
  &scope=openid%20profile%20email
  &state=...
  &code_challenge=...
  &code_challenge_method=S256
```

The user authenticates with authx-rs, and authx-rs redirects back to the SPA with a code.

## 4. Exchange the code at `/token`

The SPA backend-for-frontend or the SPA itself exchanges the code with PKCE:

```text
POST /oidc/token
grant_type=authorization_code
client_id=...
code=...
redirect_uri=https://app.example.com/auth/callback
code_verifier=...
```

The token response includes:

- JWT access token
- optional refresh token
- optional ID token

## 5. Read identity claims

Use:

- `/oidc/userinfo` for runtime claims
- `/oidc/jwks` to verify tokens in downstream services

## Practical note

If your SPA is same-origin with authx-rs, session-based auth is often simpler. Use the OIDC provider mode when you specifically need standards-based client interoperability across separate apps or services.

## Related docs

- [OIDC Provider](/concepts/oidc-provider/)
- [Session vs Token Strategy](/concepts/session-vs-token/)
