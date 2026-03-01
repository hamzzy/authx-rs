---
title: Route Handlers
description: Built-in Axum route handlers mounted by AuthxState::router().
---

`AuthxState::router()` mounts these handlers under whatever path prefix you nest it at:

## Auth endpoints

| Method | Path | Body / Params | Response |
|---|---|---|---|
| `POST` | `/sign-up` | `{ "email", "password" }` | `{ "token", "user", "session" }` |
| `POST` | `/sign-in` | `{ "email", "password" }` | `{ "token", "user", "session" }` |
| `POST` | `/sign-out` | — (session cookie) | `204 No Content` |
| `POST` | `/sign-out/all` | — (session cookie) | `204 No Content` |
| `GET`  | `/session` | — (session cookie) | `{ "user", "session" }` |
| `GET`  | `/sessions` | — (session cookie) | `[ Session, … ]` |
| `DELETE` | `/sessions/:id` | — (session cookie) | `204 No Content` |

## Error responses

All errors return JSON:

```json
{
  "error": "invalid_credentials",
  "message": "invalid credentials"
}
```

| Error code | HTTP status | Meaning |
|---|---|---|
| `invalid_credentials` | 401 | Wrong email or password |
| `user_not_found` | 404 | Email not registered |
| `session_not_found` | 401 | Session expired or invalid |
| `email_taken` | 409 | Email already registered |
| `email_not_verified` | 403 | Must verify email first |
| `invalid_token` | 401 | Token expired or already used |
| `account_locked` | 429 | Too many failed attempts |
| `weak_password` | 422 | Password too short |
| `forbidden` | 403 | Insufficient permissions |
| `internal_error` | 500 | Server-side error |

## Adding custom routes

```rust
use axum::routing::get;

let auth_router = state.router()
    .route("/me", get(me_handler)); // add to the auth sub-router

// Or on the root router:
let app = Router::new()
    .route("/me",  get(me_handler))
    .nest("/auth", state.router());
```
