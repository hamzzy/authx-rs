---
title: Admin Dashboard
description: Embedded HTMX-powered admin UI for managing users, sessions, OIDC clients, and federation providers.
---

`authx-dashboard` is a self-contained Axum router that serves an embedded admin dashboard — no separate deployment, no Node.js, no build step.

## Features

- List, search, and create users
- Ban and unban users (with reason)
- View and revoke active sessions per user
- Stat overview (total users, banned, unverified)
- List/create OIDC clients
- List/create OIDC federation providers
- Secured by admin bearer token — token prompt in the browser UI

## Mounting

```toml title="Cargo.toml"
authx-dashboard = { path = "crates/authx-dashboard" }
```

```rust
use authx_dashboard::DashboardState;
use authx_core::events::EventBus;

let events    = EventBus::new();
let dashboard = DashboardState::new(store.clone(), events.clone(), 86400);

let app = Router::new()
    .nest("/_authx", dashboard.router("my-secret-admin-token"))
    .nest("/auth",   auth_router)
    .layer(SessionLayer::new(store));
```

The dashboard is now available at `/_authx/`.

## Security

- All `/api/*` routes require `Authorization: Bearer <admin_token>`
- The root HTML page is served without authentication so the login form can be displayed
- Tokens are stored in `sessionStorage` — cleared when the browser tab closes
- Federation provider `client_secret` is encrypted at rest using `AUTHX_ENCRYPTION_KEY`

## REST API

The dashboard exposes a JSON API you can call from your own tooling:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users` | List users (`?offset=0&limit=25`) |
| `POST` | `/api/users` | Create user (`{"email": "…"}`) |
| `GET` | `/api/users/:id` | Get single user |
| `POST` | `/api/users/:id/ban` | Ban user (`{"reason": "…"}`) |
| `DELETE` | `/api/users/:id/ban` | Unban user |
| `GET` | `/api/users/:id/sessions` | List sessions |
| `DELETE` | `/api/users/:id/sessions` | Revoke all sessions |
| `GET` | `/api/oidc/clients` | List OIDC clients |
| `POST` | `/api/oidc/clients` | Create OIDC client |
| `GET` | `/api/oidc/federation` | List federation providers |
| `POST` | `/api/oidc/federation` | Create federation provider |

All routes return JSON and require `Authorization: Bearer <token>`.

## Admin token

Treat the admin token as a high-privilege credential:

- Generate with `openssl rand -hex 32`
- Store in an environment variable or secret manager
- Rotate periodically
- Never commit to source control

For federation provider secret encryption, also set:

```bash
export AUTHX_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```
