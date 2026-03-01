---
title: CSRF Protection
description: Origin and Referer header validation for mutating requests.
---

authx uses a **trusted-origin check** for CSRF protection on all mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`). This is the same approach used by Django, Rails, and Next.js.

## How it works

For each mutating request, authx checks that at least one of `Origin` or `Referer` headers is present **and** matches a trusted origin. Requests without a matching header are rejected with `403 Forbidden`.

GET requests are always permitted (they must be idempotent).

## Setup

```rust
use authx_axum::{csrf_middleware, CsrfConfig};
use axum::middleware;

let csrf = CsrfConfig::new([
    "https://app.example.com",
    "https://admin.example.com",
]);

// Apply as a route layer on your auth router
let auth_router = Router::new()
    .nest("/auth", auth_handlers)
    .route_layer(middleware::from_fn_with_state(csrf, csrf_middleware));
```

## Multiple origins

```rust
let origins: Vec<&str> = std::env::var("TRUSTED_ORIGINS")
    .unwrap_or_default()
    .split(',')
    .map(str::trim)
    .collect();

let csrf = CsrfConfig::new(origins);
```

## Why not CSRF tokens?

Synchronizer token pattern requires server-side state or double-submit cookies. For API-first applications that rely on `Authorization` headers or `SameSite=Lax` cookies, origin checking is both simpler and equally effective — browsers enforce the `Origin` header and scripts cannot fake it.

For traditional form-based applications, consider adding a CSRF token layer on top.

## curl / API clients

curl and non-browser HTTP clients don't send `Origin` by default. Add it explicitly when testing:

```bash
curl -X POST https://app.example.com/auth/sign-in \
     -H 'Origin: https://app.example.com' \
     -H 'Content-Type: application/json' \
     -d '{"email":"a@b.com","password":"pass"}'
```
