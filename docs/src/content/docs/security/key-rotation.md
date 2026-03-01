---
title: Key Rotation
description: Zero-downtime Ed25519 JWT signing key rotation.
---

`KeyRotationStore` manages multiple Ed25519 signing key versions. New tokens are signed with the latest key; old tokens are still verifiable as long as their signing key version is retained.

## Setup

```rust
use authx_core::crypto::key_store::KeyRotationStore;

// Keep at most 3 key versions in memory
let store = KeyRotationStore::new(3);

// Add the initial key
store.add_key("v1", PRIVATE_KEY_PEM, PUBLIC_KEY_PEM)?;
```

## Signing a token

```rust
let token = store.sign(
    user_id,
    3600,                          // TTL in seconds
    serde_json::json!({ "role": "admin" }), // extra claims
)?;
```

## Verifying a token

```rust
let claims = store.verify(&token)?;
// Tries the newest key first, falls back through older versions
// Returns Err if no key can verify the token
```

## Rotating keys

```rust
// Promote a new key — old key stays for existing token validation
store.rotate("v2", NEW_PRIVATE_PEM, NEW_PUBLIC_PEM)?;

// New tokens now use v2. Tokens signed by v1 still valid.
// Once max_versions is exceeded, oldest key is evicted.
```

## Rotation strategy

| Step | Action |
|---|---|
| 1. Generate new key pair | `openssl genpkey -algorithm Ed25519 > new_key.pem` |
| 2. Load new key | `store.rotate("v2", new_priv, new_pub)` |
| 3. Wait for old tokens to expire | Duration = max session TTL |
| 4. Old key evicted automatically | After `max_versions` exceeded |

Zero downtime — users with tokens signed by the old key continue to authenticate until those tokens naturally expire.

## Loading keys from environment

```rust
let private_pem = std::env::var("JWT_PRIVATE_KEY").expect("JWT_PRIVATE_KEY required");
let public_pem  = std::env::var("JWT_PUBLIC_KEY").expect("JWT_PUBLIC_KEY required");

store.add_key("v1", &private_pem, &public_pem)?;
```
