---
title: Email + Password
description: Traditional email and password authentication with Argon2id hashing.
---

import { Aside } from '@astrojs/starlight/components';

The `EmailPasswordService` handles registration, sign-in, sign-out, and session management using Argon2id password hashing.

## Setup

```rust
use authx_plugins::EmailPasswordService;
use authx_core::{brute_force::LockoutConfig, events::EventBus};
use authx_storage::memory::MemoryStore;
use std::time::Duration;

let store  = MemoryStore::new();
let events = EventBus::new();

// Basic — no lockout
let svc = EmailPasswordService::new(store.clone(), events.clone(), 3600);

// With brute-force lockout
let lockout = LockoutConfig::new(5, Duration::from_secs(15 * 60));
let svc = EmailPasswordService::new(store.clone(), events.clone(), 3600)
    .with_lockout(lockout);
```

## Sign up

```rust
let user = svc.sign_up("alice@example.com", "securepassword123").await?;
// Returns Err(AuthError::EmailTaken) if already registered
// Returns Err(AuthError::WeakPassword) if password < 8 chars
```

## Sign in

```rust
let resp = svc.sign_in("alice@example.com", "securepassword123", "127.0.0.1").await?;

resp.token    // raw session token — send to client (cookie or header)
resp.session  // Session model with id, expires_at, ip_address, …
resp.user     // User model
```

After `max_failures` wrong passwords within the lockout window, the account is locked and further attempts return `Err(AuthError::AccountLocked)`.

## Sign out

```rust
// Sign out current session
svc.sign_out(session_token).await?;

// Sign out all sessions (all devices)
svc.sign_out_all(user_id).await?;
```

## List sessions

```rust
let sessions = svc.list_sessions(user_id).await?;
// Returns all non-expired sessions for the user
```

## Axum integration

The built-in Axum handlers expose these endpoints automatically when you call `state.router()`:

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/sign-up` | Register |
| `POST` | `/auth/sign-in` | Sign in |
| `POST` | `/auth/sign-out` | Sign out current session |
| `POST` | `/auth/sign-out/all` | Sign out all sessions |
| `GET`  | `/auth/session` | Current session info |
| `GET`  | `/auth/sessions` | List all sessions |
| `DELETE` | `/auth/sessions/:id` | Revoke specific session |

## Password requirements

<Aside type="caution">
authx enforces a minimum password length of 8 characters. For production apps, consider adding your own strength validation (zxcvbn, etc.) before calling `sign_up`.
</Aside>

Passwords are hashed with **Argon2id** using parameters that meet OWASP recommendations:

| Parameter | Value |
|---|---|
| Memory | 65536 KiB (64 MiB) |
| Iterations | 3 |
| Parallelism | 4 |
| Output length | 32 bytes |
