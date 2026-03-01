---
title: API Keys
description: Long-lived programmatic access tokens with scope-based permissions.
---

API keys give machine clients authenticated access without a session cookie or browser flow.

## How they work

1. The raw key (64-char hex string) is shown **once** on creation and never stored.
2. Only the **SHA-256 hash** of the key is persisted.
3. On authentication, the caller presents the raw key; authx hashes it and does a lookup.
4. Each key has a 8-character prefix stored in plaintext for display purposes (`auth_a1b2c3d4…`).

## Setup

```rust
use authx_plugins::ApiKeyService;

let svc = ApiKeyService::new(store.clone());
```

## Create a key

```rust
let resp = svc.create(
    user_id,
    Some(org_id),           // optional org scope
    "CI pipeline".into(),   // human-readable name
    vec!["read".into(), "deploy".into()], // scopes
    Some(Utc::now() + chrono::Duration::days(365)), // optional expiry
).await?;

// Show resp.raw_key to the user exactly once
println!("Save this key: {}", resp.raw_key);
// resp.key contains the ApiKey model (no raw key)
```

## List keys

```rust
let keys = svc.list(user_id).await?;
// Returns Vec<ApiKey> — key_hash is included but raw key is gone forever
```

## Revoke a key

```rust
svc.revoke(user_id, key_id).await?;
// Enforces ownership — user_id must own the key
```

## Authenticate an incoming request

```rust
// Extract raw key from Authorization header: "Bearer <raw_key>"
let key = svc.authenticate(&raw_key).await?;
// Returns Err(AuthError::InvalidToken) if unknown, expired, or revoked
// Updates last_used_at automatically

key.user_id   // who owns this key
key.scopes    // Vec<String>
key.org_id    // optional org context
```

## Axum extractor pattern

```rust
use axum::{extract::TypedHeader, headers::{Authorization, Bearer}};

async fn api_handler(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    State(svc): State<ApiKeyService<MemoryStore>>,
) -> impl IntoResponse {
    match svc.authenticate(auth.token()).await {
        Ok(key) => /* proceed */,
        Err(_)  => StatusCode::UNAUTHORIZED.into_response(),
    }
}
```
