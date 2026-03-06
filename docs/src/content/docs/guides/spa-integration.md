---
title: SPA & Backend Integration
description: End-to-end guide for connecting a React, Vue, or other single-page application to an Axum backend powered by authx-rs.
---

This guide walks through the recommended patterns for authenticating users in a single-page application (SPA) that talks to an Axum backend using authx-rs. It covers session-based auth (the default for browsers), OIDC/SSO federation, and token-based auth for non-browser clients.

## Architecture overview

```
┌─────────────────────┐         HTTPS          ┌──────────────────────────┐
│   SPA (React/Vue)   │ ◄────────────────────► │  Axum + authx-rs         │
│                     │   fetch() with cookies  │                          │
│  localhost:5173     │                         │  localhost:3000           │
│  or app.example.com │                         │  or api.example.com      │
└─────────────────────┘                         └──────────┬───────────────┘
                                                           │
                                                           ▼
                                                  ┌────────────────┐
                                                  │   PostgreSQL   │
                                                  │   (or Memory)  │
                                                  └────────────────┘
```

The SPA never handles raw passwords or tokens directly. All auth state lives in `HttpOnly` session cookies that the browser manages automatically. The backend is the single source of truth for authentication and authorization.

## Session-based auth for SPAs (recommended)

Cookie-based sessions are the recommended approach for any browser-based application. authx-rs sets a secure `authx_session` cookie on sign-in and validates it on every request via `SessionLayer`.

### Backend setup

```rust
use std::time::Duration;

use axum::{Router, routing::get, response::Json};
use tower_http::cors::{CorsLayer, AllowOrigin};
use tower_http::trace::TraceLayer;

use authx_axum::{
    csrf_middleware, AuthxState, CsrfConfig,
    RateLimitConfig, RateLimitLayer, RequireAuth, SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_storage::postgres::PgStore;

#[tokio::main]
async fn main() {
    let store = PgStore::connect("postgres://localhost/myapp").await.unwrap();

    let lockout = LockoutConfig::new(5, Duration::from_secs(900));

    let state = AuthxState::new_with_lockout(
        store.clone(),
        60 * 60 * 24 * 30, // 30-day sessions
        true,               // Secure cookies (HTTPS only)
        lockout,
    );

    // Trusted origins — must match where the SPA is served from
    let csrf = CsrfConfig::new(["https://app.example.com"]);
    let rl   = RateLimitLayer::new(RateLimitConfig::new(20, Duration::from_secs(60)));

    let auth_router = state
        .router()
        .layer(rl)
        .route_layer(axum::middleware::from_fn_with_state(csrf, csrf_middleware));

    // CORS — allow the SPA origin and permit credentials (cookies)
    let cors = CorsLayer::new()
        .allow_origin("https://app.example.com".parse::<http::HeaderValue>().unwrap())
        .allow_credentials(true)
        .allow_headers([http::header::CONTENT_TYPE])
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::DELETE]);

    let app = Router::new()
        .route("/me", get(me))
        .nest("/auth", auth_router)
        .layer(SessionLayer::new(store))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn me(RequireAuth(identity): RequireAuth) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": identity.user.id,
        "email":   identity.user.email,
    }))
}
```

Key points:

- **`CorsLayer`** must include `.allow_credentials(true)` so the browser sends cookies cross-origin.
- **`CsrfConfig`** must list every origin the SPA is served from. authx rejects mutating requests (`POST`, `PUT`, `DELETE`) that lack a matching `Origin` header.
- **`secure_cookies: true`** in production ensures cookies are only sent over HTTPS.

### Cookie behavior

authx-rs sets the `authx_session` cookie with these flags:

| Flag | Value | Why |
|---|---|---|
| `HttpOnly` | `true` | JavaScript cannot read the session token |
| `SameSite` | `Lax` | Browser sends cookie on same-site navigations and top-level GET redirects |
| `Secure` | `true` (prod) | Cookie only sent over HTTPS |
| `Path` | `/` | Available to all routes |
| `Max-Age` | session TTL | Auto-expires in the browser |

Because the cookie is `HttpOnly`, your SPA code never sees the session token. This eliminates an entire class of XSS-based session theft.

### Sign-up from the SPA

```typescript
// auth.ts — thin wrapper around fetch

const API = "https://api.example.com";

export async function signUp(email: string, password: string) {
  const res = await fetch(`${API}/auth/sign-up`, {
    method: "POST",
    credentials: "include", // send and receive cookies
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error ?? "Sign-up failed");
  }

  return res.json(); // { user_id, session_id, token }
}
```

### Sign-in from the SPA

```typescript
export async function signIn(email: string, password: string) {
  const res = await fetch(`${API}/auth/sign-in`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const err = await res.json();
    // err.error may be "account_locked" after too many failed attempts
    throw new Error(err.error ?? "Sign-in failed");
  }

  return res.json(); // { user_id, session_id, token }
}
```

After a successful response, the browser stores the `authx_session` cookie automatically. All subsequent `fetch()` calls with `credentials: "include"` will attach it.

### Sign-out from the SPA

```typescript
export async function signOut() {
  await fetch(`${API}/auth/sign-out`, {
    method: "POST",
    credentials: "include",
  });
}

// Sign out from all devices
export async function signOutAll() {
  await fetch(`${API}/auth/sign-out/all`, {
    method: "POST",
    credentials: "include",
  });
}
```

### Fetching protected resources

```typescript
export async function getMe() {
  const res = await fetch(`${API}/me`, {
    credentials: "include",
  });

  if (res.status === 401) {
    // Session expired or invalid — redirect to login
    window.location.href = "/login";
    return null;
  }

  return res.json();
}
```

### Session check on app load

A common pattern is to call `/auth/session` when the SPA first loads to determine if the user is already authenticated:

```typescript
// App.tsx (React example)
import { useEffect, useState } from "react";

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("https://api.example.com/auth/session", {
      credentials: "include",
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setUser(data))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div>Loading...</div>;
  if (!user) return <LoginPage />;
  return <Dashboard user={user} />;
}
```

## OIDC/SSO integration for SPAs

authx-rs supports OIDC federation for enterprise SSO (Okta, Azure AD, Google Workspace, etc.). The SPA still uses a browser redirect, but the current built-in callback ends with a JSON response plus `Set-Cookie`, not a final redirect back into the SPA.

### Flow diagram

```
1. User clicks "Sign in with Okta" in the SPA
2. SPA redirects to:
     https://api.example.com/auth/federation/okta/begin?redirect_uri=https://api.example.com/auth/federation/okta/callback
3. Backend generates PKCE + state, redirects browser to Okta
4. User authenticates at Okta
5. Okta redirects to:
     https://api.example.com/auth/federation/okta/callback?code=...&state=...
6. Backend exchanges code for tokens, creates user + session, sets cookie
7. Backend responds with JSON and a valid session cookie
8. The browser can then navigate to the SPA or another authenticated route
```

### Backend setup for federation

```rust
use std::sync::Arc;
use authx_axum::oidc_federation_router;
use authx_plugins::oidc_federation::OidcFederationService;

// Configure federation providers (typically from DB or config) and keep a
// stable 32-byte encryption key for provider secrets and upstream tokens.
let encryption_key: [u8; 32] = /* load from config */;
let federation_svc = Arc::new(OidcFederationService::new(
    store.clone(),
    60 * 60 * 24 * 30,
    encryption_key,
));

let federation_router = oidc_federation_router(federation_svc);

let app = Router::new()
    .nest("/auth", auth_router)
    .nest("/auth/federation", federation_router)
    .layer(SessionLayer::new(store))
    .layer(cors)
    .layer(TraceLayer::new_for_http());
```

The federation router exposes two routes per provider:

| Route | Method | Purpose |
|---|---|---|
| `/:provider/begin` | `GET` | Starts the OIDC flow; redirects to the IdP |
| `/:provider/callback` | `GET` | Handles the IdP callback; creates session |

### Frontend: initiating SSO

```typescript
export function startSso(provider: string) {
  // Full-page redirect — not a fetch() call
  window.location.href =
    `https://api.example.com/auth/federation/${provider}/begin` +
    `?redirect_uri=https://api.example.com/auth/federation/${provider}/callback`;
}
```

```html
<!-- Login page -->
<button onclick="startSso('okta')">Sign in with Okta</button>
<button onclick="startSso('azure')">Sign in with Azure AD</button>
<button onclick="startSso('google')">Sign in with Google Workspace</button>
```

### Frontend: handling the current callback model

Today, the built-in federation callback is an authx endpoint, not a SPA route. It sets the authx session cookie and returns JSON. If you need a final redirect back into the SPA, add a thin wrapper route around `OidcFederationService` in your own app.

That wrapper typically:

- stores any final destination you care about
- calls the federation service callback
- sets the cookie
- returns `302 Found` to the SPA route you want

## Token-based auth alternative (mobile and CLI)

Session cookies are ideal for browsers, but mobile apps and CLI tools cannot use them. For these clients, use access tokens directly.

### When to use tokens instead of cookies

| Client | Auth method |
|---|---|
| Browser SPA | Session cookies (recommended) |
| Native mobile app | Access token in `Authorization` header |
| CLI tool | Device authorization grant or access token |
| Server-to-server | API keys (see [API Keys](/auth/api-keys/)) |

### Using the session token directly

The sign-in response includes a `token` field. Non-browser clients can store it and send it as a cookie header manually:

```typescript
// React Native or Electron example
const { token } = await signIn(email, password);

// Store securely (e.g., Keychain on iOS, credential store on desktop)
await SecureStore.setItem("authx_token", token);

// Use in subsequent requests
const res = await fetch("https://api.example.com/me", {
  headers: {
    Cookie: `authx_session=${token}`,
  },
});
```

### Device authorization grant for CLI tools

authx-rs includes an OIDC provider with device authorization grant support, suitable for headless CLI authentication:

```
1. CLI requests a device code from the backend
2. Backend returns a user_code and verification URL
3. CLI displays: "Open https://api.example.com/device and enter code: ABCD-1234"
4. User opens URL in browser, authenticates, enters code
5. CLI polls the token endpoint until approved
6. CLI receives an access token
```

The device authorization endpoint is available when the OIDC provider router is mounted:

```rust
use authx_axum::{oidc_provider_router, OidcProviderState};
use authx_plugins::oidc_provider::{OidcProviderConfig, OidcProviderService};

let oidc_config = OidcProviderConfig { /* ... */ };
let oidc_svc = OidcProviderService::new(store.clone(), oidc_config.clone());

let provider_state = OidcProviderState {
    service: Arc::new(oidc_svc),
    config: oidc_config,
};

let oidc_router = oidc_provider_router(provider_state);

let app = Router::new()
    .nest("/oidc", oidc_router)
    // ...
```

This exposes `/oidc/device/authorize` (POST), `/oidc/device` (GET, verification page), and `/oidc/device/verify` (POST).

## Production checklist

Before deploying your SPA + authx-rs backend to production, verify the following:

### HTTPS required

- Serve both the SPA and the API over HTTPS. Without it, `Secure` cookies will not be sent and session tokens are exposed to network interception.
- Terminate TLS at your load balancer or reverse proxy (nginx, Caddy, CloudFront).

### Secure cookies enabled

```rust
let state = AuthxState::new_with_lockout(
    store.clone(),
    60 * 60 * 24 * 30,
    true,  // ← must be true in production
    lockout,
);
```

### CORS and trusted origins configured

```rust
// CORS — only allow your SPA origin
let cors = CorsLayer::new()
    .allow_origin("https://app.example.com".parse::<http::HeaderValue>().unwrap())
    .allow_credentials(true)
    .allow_headers([http::header::CONTENT_TYPE])
    .allow_methods([http::Method::GET, http::Method::POST, http::Method::DELETE]);

// CSRF — same origin list
let csrf = CsrfConfig::new(["https://app.example.com"]);
```

Do not use wildcard origins (`*`) with `allow_credentials(true)` -- browsers will reject it.

### Rate limiting

Apply rate limiting to auth endpoints to prevent credential-stuffing attacks:

```rust
use authx_axum::{RateLimitConfig, RateLimitLayer};

// 20 requests per minute per IP
let rl = RateLimitLayer::new(RateLimitConfig::new(20, Duration::from_secs(60)));

let auth_router = state
    .router()
    .layer(rl)
    .route_layer(axum::middleware::from_fn_with_state(csrf, csrf_middleware));
```

### Brute-force lockout

Configure account lockout to slow down targeted password guessing:

```rust
use authx_core::brute_force::LockoutConfig;

// Lock account after 5 failed attempts for 15 minutes
let lockout = LockoutConfig::new(5, Duration::from_secs(900));
```

When an account is locked, sign-in attempts return an `account_locked` error. The SPA should display a user-friendly message:

```typescript
try {
  await signIn(email, password);
} catch (err) {
  if (err.message === "account_locked") {
    showError("Too many failed attempts. Please try again in 15 minutes.");
  } else {
    showError("Invalid email or password.");
  }
}
```

### Summary table

| Item | Development | Production |
|---|---|---|
| HTTPS | Optional | Required |
| `secure_cookies` | `false` | `true` |
| CORS origin | `http://localhost:5173` | `https://app.example.com` |
| CSRF trusted origins | `http://localhost:5173` | `https://app.example.com` |
| Rate limiting | Optional | Required |
| Brute-force lockout | Optional | Required |
| `SameSite` | `Lax` (default) | `Lax` (default) |
