---
title: Sessions
description: How authx-rs manages user sessions.
---

## Session lifecycle

```
sign_in()
  → generate 32 random bytes  (raw token)
  → hex-encode                (64-char string — sent to client once)
  → SHA-256 hash              (stored in DB)
  → set HttpOnly cookie
  → return raw token in response body

subsequent requests
  → read cookie value (raw token)
  → SHA-256 hash
  → look up in sessions table
  → return Identity if found and not expired

sign_out()
  → SHA-256 hash cookie value
  → delete session row
  → clear cookie
```

## Session model

```rust
pub struct Session {
    pub id:          Uuid,
    pub user_id:     Uuid,
    pub token_hash:  String,         // SHA-256 of raw token
    pub device_info: serde_json::Value,
    pub ip_address:  String,
    pub org_id:      Option<Uuid>,   // active organization context
    pub expires_at:  DateTime<Utc>,
    pub created_at:  DateTime<Utc>,
}
```

## Token security

- Raw tokens are **never stored** — only their SHA-256 hash
- If the database is compromised, attackers cannot reuse tokens without inverting SHA-256
- Tokens are 32 random bytes = 256 bits of entropy — brute force is infeasible

## Cookies

`SessionLayer` sets an `authx_session` cookie with:

| Flag | Value | Purpose |
|---|---|---|
| `HttpOnly` | true | JS cannot read the token |
| `SameSite` | Lax | CSRF mitigation for cross-site requests |
| `Secure` | configurable | HTTPS-only in production |
| `Path` | `/` | Available on all routes |
| `Max-Age` | session TTL | Auto-expires in browser |

## Multi-device sessions

Users can have multiple concurrent sessions (one per device). `sign_out_all()` invalidates all of them atomically.

## Org context on sessions

A session carries `org_id` — the currently active organization. Switch it with:

```rust
org_svc.switch_org(session_id, target_org_id, user_id).await?;
```

The next request after the session update sees the new `identity.active_org`.

## Strategy choice

For when to use sessions vs OAuth/OIDC token-based auth, see:

- [Session vs Token Strategy](/concepts/session-vs-token-strategy/)
