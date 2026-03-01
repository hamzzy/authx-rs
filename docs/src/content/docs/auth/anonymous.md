---
title: Anonymous / Guest Auth
description: Create guest sessions that can be upgraded to full accounts.
---

Guest sessions let users try your app before committing to registration. When ready, they can upgrade to a full account without losing their data.

## Setup

```rust
use authx_plugins::AnonymousService;

let svc = AnonymousService::new(store.clone(), events.clone(), 3600);
```

## Create a guest session

```rust
let (user, session, token) = svc.create_guest("127.0.0.1").await?;

// user.email is "guest_<uuid>@authx.guest" — a synthetic placeholder
// user.metadata contains {"guest": true}
// token is the session token to send to the client
```

## Upgrade to a real account

```rust
let upgraded_user = svc.upgrade(
    guest_user_id,
    "alice@example.com",
    "securepassword123",
).await?;
// Err(AuthError::Forbidden) if user_id is not a guest
// Err(AuthError::EmailTaken) if email is already used
```

After upgrade, the user's existing sessions and data remain intact — only their email and credentials change.
