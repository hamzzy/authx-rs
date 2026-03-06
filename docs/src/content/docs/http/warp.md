---
title: Warp Integration
description: Direct authx-rs integration patterns for Warp applications.
---

There is no dedicated `authx-warp` crate today. Warp integration works by keeping authx at the service layer and writing a small amount of filter glue around cookies, headers, and JSON bodies.

## Recommended pattern

- keep `MemoryStore` or your real storage adapter in shared state
- wrap `EmailPasswordService`, `OrgService`, or other authx services in `Arc`
- use Warp filters to parse cookies and request bodies
- hash the raw session token and resolve the session through `SessionRepository`

## Sketch

```rust
use std::sync::Arc;

use authx_core::crypto::sha256_hex;
use authx_plugins::email_password::EmailPasswordService;
use authx_storage::{ports::{SessionRepository, UserRepository}, MemoryStore};
use warp::{Filter, Rejection, Reply};

let store = MemoryStore::new();
let auth = Arc::new(EmailPasswordService::new(
    store.clone(),
    authx_core::events::EventBus::new(),
    12,
    60 * 60 * 24 * 30,
));

let store_filter = warp::any().map(move || store.clone());
let auth_filter = warp::any().map(move || auth.clone());

let me = warp::path("me")
    .and(warp::cookie::optional("authx_session"))
    .and(store_filter.clone())
    .and_then(|token: Option<String>, store: MemoryStore| async move {
        let token = token.ok_or_else(warp::reject::not_found)?;
        let hash = sha256_hex(token.as_bytes());
        let session = store.find_by_token_hash(&hash).await.map_err(|_| warp::reject())?
            .ok_or_else(warp::reject::not_found)?;
        let user = store.find_by_id(session.user_id).await.map_err(|_| warp::reject())?
            .ok_or_else(warp::reject::not_found)?;
        Ok::<_, Rejection>(warp::reply::json(&serde_json::json!({
            "user_id": user.id,
            "email": user.email,
        })))
    });
```

## Practical note

Warp is a good fit when you want fine-grained composition, but authx does not rely on Warp-specific abstractions. Keep the integration layer small and let authx services own the auth logic.
