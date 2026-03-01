---
title: Middleware
description: Tower middleware provided by authx-axum.
---

All authx middleware follows the Tower `Layer` / `Service` pattern — compatible with any Tower-based stack (Axum, Hyper, etc.).

## SessionLayer

Resolves the `Identity` from the session cookie on every request. Injects it into request extensions so downstream extractors can access it.

```rust
use authx_axum::SessionLayer;

// Mount on the whole app — not just auth routes
app.layer(SessionLayer::new(store))
```

**Effect:** After this layer, every handler can use `RequireAuth` or `RequireRole` extractors. Unauthenticated requests pass through — handlers decide whether auth is required.

## RateLimitLayer

Per-IP sliding window rate limiter.

```rust
use authx_axum::{RateLimitLayer, RateLimitConfig};
use std::time::Duration;

app.layer(RateLimitLayer::new(
    RateLimitConfig::new(20, Duration::from_secs(60))
))
```

Returns `429 Too Many Requests` when the limit is exceeded.

## csrf_middleware

Validates `Origin` / `Referer` for mutating requests.

```rust
use authx_axum::{csrf_middleware, CsrfConfig};
use axum::middleware;

router.route_layer(middleware::from_fn_with_state(
    CsrfConfig::new(["https://app.example.com"]),
    csrf_middleware,
))
```

Returns `403 Forbidden` when origin validation fails.

## Middleware ordering

Tower applies layers from **outermost to innermost** (last `.layer()` call is outermost).

Recommended ordering from outermost to innermost:

```rust
app
  .layer(TraceLayer::new_for_http())   // 1. log everything
  .layer(SessionLayer::new(store))     // 2. resolve identity
  // rate limit applied to auth routes only via auth_router
```
