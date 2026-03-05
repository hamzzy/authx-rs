---
title: Axum Integration
description: Using authx-rs with the Axum web framework.
---

`authx-axum` provides plug-and-play integration for [Axum](https://github.com/tokio-rs/axum).

## Complete setup

```rust
use std::time::Duration;

use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;

use authx_axum::{
    csrf_middleware, AuthxState, CsrfConfig,
    RateLimitConfig, RateLimitLayer, SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_storage::memory::MemoryStore;

#[tokio::main]
async fn main() {
    let store   = MemoryStore::new();
    let lockout = LockoutConfig::new(5, Duration::from_secs(900));

    let state = AuthxState::new_with_lockout(
        store.clone(), 86400, false, lockout,
    );

    let csrf     = CsrfConfig::new(["http://localhost:3000"]);
    let rl_layer = RateLimitLayer::new(RateLimitConfig::new(20, Duration::from_secs(60)));

    let auth_router = state
        .router()
        .layer(rl_layer)
        .route_layer(axum::middleware::from_fn_with_state(csrf, csrf_middleware));

    let app = Router::new()
        .nest("/auth", auth_router)
        .layer(SessionLayer::new(store))
        .layer(TraceLayer::new_for_http());

    axum::serve(
        tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(),
        app,
    ).await.unwrap();
}
```

## AuthxState

`AuthxState<S>` holds a reference to your storage adapter and exposes `.router()` which mounts all auth endpoints under the current path prefix.

```rust
// Basic (no lockout)
let state = AuthxState::new(store, session_ttl_secs, secure_cookies);

// With lockout
let state = AuthxState::new_with_lockout(store, session_ttl_secs, secure_cookies, lockout);

// With lockout + explicit remember-me TTL policy
let state = AuthxState::new_with_lockout_and_remember_me(
    store,
    session_ttl_secs,
    remember_me_ttl_secs,
    secure_cookies,
    Some(lockout),
);
```

## SessionLayer

`SessionLayer` is a Tower middleware that resolves `Identity` from the session cookie on every incoming request. Mount it on the entire app (not just auth routes) so that any handler can access `Identity`.

```rust
.layer(SessionLayer::new(store))
```

## RequireAuth extractor

```rust
use authx_axum::RequireAuth;

async fn protected(RequireAuth(identity): RequireAuth) -> impl IntoResponse {
    Json(serde_json::json!({ "email": identity.user.email }))
}
```

Returns `401 Unauthorized` if no valid session is present.

## RequireRole extractor

```rust
use authx_axum::RequireRole;

async fn admin_only(RequireRole(identity, _): RequireRole<"admin">) -> impl IntoResponse {
    // Only reachable by users with "admin" role in their active org
}
```
