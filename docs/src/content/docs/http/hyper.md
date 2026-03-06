---
title: Hyper Integration
description: Using authx-rs directly from Hyper handlers and services.
---

Hyper integration is the lowest-level option. authx-rs fits well because the core and plugin crates do not assume any particular web framework.

## Recommended shape

- keep authx services in shared application state
- parse cookies or `x-authx-token` yourself
- hash the raw session token and resolve it through the storage layer
- build HTTP responses manually or through your own helper functions

## Sketch

```rust
use authx_core::crypto::sha256_hex;
use authx_storage::ports::{SessionRepository, UserRepository};
use hyper::{Request, Response, StatusCode};

async fn me(req: Request<hyper::body::Incoming>, state: AppState) -> Response<String> {
    let token = extract_cookie(&req, "authx_session")
        .or_else(|| extract_header(&req, "x-authx-token"));

    let Some(token) = token else {
        return response(StatusCode::UNAUTHORIZED, r#"{"error":"session_not_found"}"#);
    };

    let hash = sha256_hex(token.as_bytes());
    let session = match state.store.find_by_token_hash(&hash).await {
        Ok(Some(session)) => session,
        _ => return response(StatusCode::UNAUTHORIZED, r#"{"error":"session_not_found"}"#),
    };

    let user = match state.store.find_by_id(session.user_id).await {
        Ok(Some(user)) => user,
        _ => return response(StatusCode::NOT_FOUND, r#"{"error":"user_not_found"}"#),
    };

    response(StatusCode::OK, &format!(r#"{{"email":"{}"}}"#, user.email))
}
```

## Why this is viable

The only framework-specific work is HTTP parsing and response construction. Authentication, session creation, password verification, OIDC, organizations, and policy logic all remain inside authx services and repository traits.
