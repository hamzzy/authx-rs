---
title: Username Login
description: Username + password authentication without an email address.
---

The `UsernameService` is identical to `EmailPasswordService` but uses a username for lookup instead of an email address.

## Setup

```rust
use authx_plugins::UsernameService;

let svc = UsernameService::new(store.clone(), events.clone(), 3600);
```

## Sign up

```rust
let user = svc.sign_up(
    "alice_wonder",          // username (must be unique)
    "alice@example.com",     // email (still stored for notifications)
    "securepassword123",
).await?;
// Err(AuthError::EmailTaken) if username is already taken
```

## Sign in

```rust
let resp = svc.sign_in("alice_wonder", "securepassword123", "127.0.0.1").await?;

resp.token
resp.user
resp.session
```
