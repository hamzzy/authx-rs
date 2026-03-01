---
title: Email OTP
description: One-time passcode authentication via email.
---

Email OTP sends a short-lived single-use token to the user's email. It can serve as a primary sign-in method or as a second factor.

## Setup

```rust
use authx_plugins::EmailOtpService;

// TTL in seconds (10 minutes recommended)
let svc = EmailOtpService::new(store.clone(), events.clone(), 600);
```

## Issue an OTP

```rust
// Returns None for unknown email (prevents user enumeration)
let raw_token = svc.issue("alice@example.com").await?;

if let Some(token) = raw_token {
    // Send `token` via your email provider
    // Typically displayed as a 6-8 digit code or a clickable link
}
```

## Verify and create session

```rust
let resp = svc.verify(&token, "client-ip").await?;
// Returns Err(AuthError::InvalidToken) if expired or already used

resp.token    // session token
resp.user
resp.session
```

## Token details

| Property | Value |
|---|---|
| Format | 32 random bytes, hex-encoded (64 chars) |
| Default TTL | 10 minutes (configurable) |
| Single-use | Yes |
| Storage | SHA-256 hash only |
