---
title: Actix Web Integration
description: Using authx-rs directly with actix-web without the Axum adapter crate.
---

There is no first-party `authx-actix` crate yet. The intended pattern today is to use the framework-agnostic services from `authx-plugins`, manage cookies yourself, and resolve sessions through the storage traits.

## Runnable example

See the full example crate at [examples/actix-app](/examples/actix-app/).

It demonstrates:

- manual `authx_session` cookie creation and removal
- direct use of `EmailPasswordService`
- protected handlers that resolve the current session from a cookie or header
- sign-up, sign-in, sign-out, session inspection, and `/me`

## Minimal shape

```rust
use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer};
use authx_core::events::EventBus;
use authx_plugins::email_password::EmailPasswordService;
use authx_storage::MemoryStore;

let store = MemoryStore::new();
let events = EventBus::new();
let auth = Arc::new(EmailPasswordService::new(
    store.clone(),
    events,
    12,
    60 * 60 * 24 * 30,
));

let state = web::Data::new(AppState { store, auth });

HttpServer::new(move || {
    App::new()
        .app_data(state.clone())
        .route("/auth/sign-in", web::post().to(sign_in))
        .route("/me", web::get().to(me))
})
.bind(("127.0.0.1", 4000))?
.run()
.await?;
```

## Session resolution pattern

The key part of non-Axum integration is turning the raw cookie back into an authx session:

```rust
use authx_core::crypto::sha256_hex;
use authx_storage::ports::{SessionRepository, UserRepository};

let raw = req.cookie("authx_session").ok_or(AuthError::SessionNotFound)?;
let token_hash = sha256_hex(raw.value().as_bytes());

let session = state.store.find_by_token_hash(&token_hash).await?
    .ok_or(AuthError::SessionNotFound)?;
let user = state.store.find_by_id(session.user_id).await?
    .ok_or(AuthError::UserNotFound)?;
```

That is the whole contract: authx stores only the SHA-256 hash of the session token, so your integration layer hashes the cookie/header value before looking it up.

## When to choose this approach

Use direct Actix integration when:

- your service is already built on `actix-web`
- you want authx features without adopting Axum
- you are comfortable owning the thin HTTP adapter layer yourself
