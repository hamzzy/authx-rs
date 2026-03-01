---
title: Error Codes
description: Complete reference for all AuthError variants and their HTTP status codes.
---

All authx-rs errors are represented by the `AuthError` enum from `authx-core`. The `authx-axum` layer maps them to HTTP responses.

## Error mapping

| Variant | HTTP Status | JSON `error` field | When it occurs |
|---|---|---|---|
| `InvalidCredentials` | 401 | `invalid_credentials` | Wrong password or token |
| `UserNotFound` | 404 | `user_not_found` | Email not registered |
| `SessionNotFound` | 401 | `session_not_found` | Session expired or invalid |
| `EmailTaken` | 409 | `email_taken` | Email already registered |
| `EmailNotVerified` | 403 | `email_not_verified` | Action requires verified email |
| `InvalidToken` | 401 | `invalid_token` | One-time token expired or reused |
| `AccountLocked` | 429 | `account_locked` | Too many failed sign-in attempts |
| `WeakPassword` | 422 | `weak_password` | Password too short |
| `Forbidden(String)` | 403 | `forbidden` | RBAC/ABAC policy denied |
| `HashError(String)` | 500 | `internal_error` | Argon2 hashing failure |
| `EncryptionError(String)` | 500 | `internal_error` | AES-GCM encryption failure |
| `Storage(StorageError)` | 500 | `internal_error` | Database error |
| `Internal(String)` | 500 | `internal_error` | Unexpected internal error |

## StorageError variants

`AuthError::Storage` wraps a `StorageError`:

| Variant | Meaning |
|---|---|
| `NotFound` | Record does not exist |
| `Conflict(String)` | Unique constraint violation |
| `Database(String)` | Raw database error |

## Error response format

```json
{
  "error": "invalid_credentials",
  "message": "invalid credentials"
}
```

- `error` — machine-readable code, stable across versions
- `message` — human-readable description from `thiserror` `#[error]` attribute

## In Rust code

```rust
use authx_core::error::AuthError;

match result {
    Err(AuthError::InvalidCredentials)  => { /* show generic login error */ }
    Err(AuthError::AccountLocked)       => { /* show lockout message */ }
    Err(AuthError::Forbidden(reason))   => { /* log reason, show 403 page */ }
    Err(e)                              => { /* unexpected — log and surface 500 */ }
    Ok(resp)                            => { /* success */ }
}
```
