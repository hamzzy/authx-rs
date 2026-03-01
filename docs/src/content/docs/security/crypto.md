---
title: Passwords & Crypto
description: Cryptographic primitives used throughout authx-rs.
---

## Password hashing — Argon2id

All passwords are hashed using **Argon2id** (the winner of the Password Hashing Competition):

| Parameter | Value | OWASP recommendation |
|---|---|---|
| Variant | Argon2id | Argon2id |
| Memory | 65,536 KiB (64 MiB) | ≥ 19 MiB |
| Iterations | 3 | ≥ 2 |
| Parallelism | 4 | — |
| Output length | 32 bytes | ≥ 32 bytes |

```rust
use authx_core::crypto::{hash_password, verify_password};

let hash = hash_password("hunter2")?;
let ok   = verify_password(&hash, "hunter2")?; // true
```

## Token generation and storage

Raw tokens (session tokens, magic links, API keys) are generated as 32 random bytes then hex-encoded:

```rust
use rand::Rng;
use hex;

let raw: [u8; 32] = rand::thread_rng().gen();
let token         = hex::encode(raw); // 64-char hex string — sent to client
let stored        = sha256_hex(token.as_bytes()); // only this is persisted
```

**The raw token is never stored.** If the database is compromised, tokens cannot be replayed.

## AES-256-GCM encryption

OAuth access/refresh tokens, OIDC client secrets, and other sensitive values are encrypted at rest:

```rust
use authx_core::crypto::{encrypt, decrypt};

let key        = // 32-byte key from environment
let ciphertext = encrypt(&key, plaintext_bytes)?;
let plaintext  = decrypt(&key, &ciphertext)?;
```

A fresh 12-byte random nonce is generated per encryption call — identical plaintexts produce different ciphertexts.

## JWT signing — EdDSA (Ed25519)

Session JWTs are signed with **Ed25519** keys via the `jsonwebtoken` crate. Ed25519 is:
- Faster to sign and verify than RSA-2048
- Smaller signatures (64 bytes vs ~256 bytes)
- Resistant to timing attacks (constant-time operations)

```rust
use authx_core::crypto::key_store::KeyRotationStore;

let ks = KeyRotationStore::new(3); // keep 3 key versions
ks.add_key("v1", PRIVATE_PEM, PUBLIC_PEM)?;

let token  = ks.sign(user_id, 3600, extra_claims)?;
let claims = ks.verify(&token)?; // tries newest key first, falls back
```

## SHA-256 hashing

Used for token fingerprinting and backup code storage:

```rust
use authx_core::crypto::sha256_hex;

let hash = sha256_hex(b"some-raw-token");
```
