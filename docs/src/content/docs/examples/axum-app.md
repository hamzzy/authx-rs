---
title: Axum App Example
description: Full working Axum integration with all security features enabled.
---

The `examples/axum-app` crate is a complete, runnable demo showing every authx-rs feature in a single binary.

## Running the example

```bash
git clone https://github.com/hamzzy/authx-rs
cd authx-rs
cargo run -p axum-app
```

The server starts at `http://localhost:3000`.

Open `http://localhost:3000/` for a small index page with the seeded demo routes.

## What it demonstrates

- `MemoryStore` (zero config — no DB required)
- `SessionLayer` — resolves Identity on every request
- `RateLimitLayer` — 20 requests per minute per IP on `/auth/*`
- CSRF trusted-origin check on all mutating endpoints
- Cookie-based session management (HttpOnly, SameSite=Lax)
- Per-device session listing and revocation
- Brute-force lockout after 5 failures within 15 minutes
- `RequireAuth` extractor protecting `/me`
- OIDC provider endpoints under `/oidc`
- Seeded public OIDC demo client with `/demo/oidc/login`
- Seeded federation provider named `self` with `/demo/sso?provider=self`

## Test it with curl

```bash
# Register
curl -s -X POST http://localhost:3000/auth/sign-up \
     -H 'Content-Type: application/json' \
     -H 'Origin: http://localhost:3000' \
     -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

# Sign in — saves session cookie to /tmp/jar
curl -s -c /tmp/jar -X POST http://localhost:3000/auth/sign-in \
     -H 'Content-Type: application/json' \
     -H 'Origin: http://localhost:3000' \
     -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

# Protected route
curl -s -b /tmp/jar http://localhost:3000/me

# List active sessions
curl -s -b /tmp/jar http://localhost:3000/auth/sessions

# Sign out all devices
curl -s -b /tmp/jar -X POST http://localhost:3000/auth/sign-out/all \
     -H 'Origin: http://localhost:3000'
```

## Health check

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

## Demo OIDC provider flow

After signing in locally, open:

```text
http://localhost:3000/demo/oidc/login
```

That route starts an authorization-code flow against authx's own embedded OIDC provider and renders the resulting token response plus userinfo.

## Demo federation flow

After signing in locally, open:

```text
http://localhost:3000/demo/sso?provider=self
```

The example seeds a federation provider called `self` that points back at the same app's OIDC provider. This demonstrates the federation plumbing without requiring an external Okta or Azure tenant.
