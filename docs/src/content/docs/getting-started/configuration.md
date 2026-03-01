---
title: Configuration
description: Environment variables and runtime configuration for authx-rs.
---

authx-rs is configured through code, but all values can be driven by environment variables when using the CLI or building your own server binary.

## Environment variables (CLI)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL URL. If unset, in-memory store is used |
| `AUTHX_BIND` | `0.0.0.0:3000` | Address to listen on |
| `AUTHX_SESSION_TTL` | `2592000` (30 days) | Session lifetime in seconds |
| `AUTHX_SECURE_COOKIES` | `false` | Require HTTPS-only cookies (set `true` in production) |
| `AUTHX_TRUSTED_ORIGINS` | `http://localhost:3000` | Comma-separated CSRF-safe origins |
| `AUTHX_RATE_LIMIT` | `30` | Max auth requests per IP per minute |
| `AUTHX_LOCKOUT_FAILURES` | `5` | Failed attempts before account lockout |
| `AUTHX_LOCKOUT_MINUTES` | `15` | Lockout window in minutes |

## In-code configuration

### Session TTL and security

```rust
let state = AuthxState::new_with_lockout(
    store,
    60 * 60 * 24 * 30, // session TTL: 30 days
    true,               // secure_cookies: true in production
    LockoutConfig::new(5, Duration::from_secs(900)),
);
```

### CSRF trusted origins

```rust
let csrf = CsrfConfig::new([
    "https://app.example.com",
    "https://admin.example.com",
]);
```

### Rate limiting

```rust
let rate_limit = RateLimitLayer::new(
    RateLimitConfig::new(
        30,                        // max requests
        Duration::from_secs(60),   // per window
    )
);
```

### Brute-force lockout

```rust
let lockout = LockoutConfig::new(
    5,                             // max failures
    Duration::from_secs(15 * 60), // sliding window
);

let svc = EmailPasswordService::new(store, events, 3600)
    .with_lockout(lockout);
```

### PostgreSQL connection pool

```rust
let store = PostgresStore::connect("postgres://user:pass@host/dbname").await?;
PostgresStore::migrate(&store.pool).await?; // runs bundled migrations
```

## Production checklist

- [ ] `DATABASE_URL` points to a real PostgreSQL instance
- [ ] `AUTHX_SECURE_COOKIES=true` (requires HTTPS)
- [ ] `AUTHX_TRUSTED_ORIGINS` lists only your actual frontend origins
- [ ] Rate limit and lockout thresholds tuned for your traffic
- [ ] `RUST_LOG=info` or `warn` — not `debug` in production
- [ ] Run migrations before starting (`authx migrate` or `PostgresStore::migrate`)
