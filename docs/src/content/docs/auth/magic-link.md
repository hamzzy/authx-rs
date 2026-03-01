---
title: Magic Link
description: Passwordless sign-in via single-use email tokens.
---

import { Aside } from '@astrojs/starlight/components';

Magic links let users sign in by clicking a tokenised URL sent to their email — no password required.

<Aside>
authx generates and validates the token. **You are responsible for sending the email.** This keeps authx email-provider agnostic (Resend, SendGrid, SES, Postmark — all work).
</Aside>

## Setup

```rust
use authx_plugins::MagicLinkService;

// TTL in seconds (15 minutes is a sensible default)
let svc = MagicLinkService::new(store.clone(), events.clone(), 900);
```

## Issue a link

```rust
// Returns None for unknown email (no enumeration — safe to tell the user
// "if this email exists, a link was sent")
let raw_token = svc.request_link("alice@example.com").await?;

if let Some(token) = raw_token {
    let link = format!("https://app.example.com/auth/magic?token={token}");
    // send `link` via your email provider
}
```

## Verify and create session

```rust
// User clicks the link, your handler extracts the token from the query string
let resp = svc.verify(&token, "client-ip-address").await?;
// Returns Err(AuthError::InvalidToken) if expired or already used

resp.token    // session token for the client
resp.user
resp.session
```

Tokens are **single-use** — a second call with the same token returns `InvalidToken`.

## Token details

| Property | Value |
|---|---|
| Format | 32 random bytes, hex-encoded (64 chars) |
| Storage | SHA-256 hash only — raw token never persisted |
| Default TTL | Configurable (typically 15 minutes) |
| Single-use | Yes — consumed on first successful verify |
