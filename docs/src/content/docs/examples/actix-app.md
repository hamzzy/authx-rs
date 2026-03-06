---
title: Actix App Example
description: Direct actix-web integration example using authx-rs services and manual session cookies.
---

The `examples/actix-app` crate shows how to integrate authx-rs without `authx-axum`.

## Running the example

```bash
cargo run -p actix-app
```

The server starts at `http://localhost:4000`.

## What it demonstrates

- `actix-web` handlers using `EmailPasswordService` directly
- manual `authx_session` cookie creation and removal
- protected routes via session lookup in `MemoryStore`
- lockout-enabled sign-in flow
- JSON error mapping from `AuthError` to HTTP status codes

## Test it with curl

```bash
# Register
curl -s -X POST http://localhost:4000/auth/sign-up \
     -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

# Sign in
curl -s -c /tmp/actix-jar -X POST http://localhost:4000/auth/sign-in \
     -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

# Current session
curl -s -b /tmp/actix-jar http://localhost:4000/auth/session

# Protected route
curl -s -b /tmp/actix-jar http://localhost:4000/me

# Sign out all sessions
curl -s -b /tmp/actix-jar -X POST http://localhost:4000/auth/sign-out/all
```

## Why this example exists

It demonstrates the exact portability boundary in authx-rs:

- auth logic lives in `authx-core`, `authx-storage`, and `authx-plugins`
- only the HTTP adapter code is framework-specific
