---
title: Email OTP (as MFA)
description: Use email OTP as a second factor on top of password authentication.
---

Email OTP can be layered on top of password authentication to create a two-step sign-in flow.

## Pattern

```rust
use authx_plugins::{EmailPasswordService, EmailOtpService};

// Step 1 — verify password (don't create a full session yet)
let user = password_svc.verify_credentials("alice@example.com", "password").await?;

// Step 2 — issue OTP to their email
let token = otp_svc.issue(&user.email).await?.unwrap();
// send token via email

// Step 3 — user submits OTP code; create full session
let resp = otp_svc.verify(&token, "client-ip").await?;
```

This pattern requires your application to track the intermediate "password verified but MFA pending" state — typically a short-lived signed cookie or a temporary session flag in your own session store.

## When to use Email OTP vs TOTP

| | Email OTP | TOTP |
|---|---|---|
| Requires device setup | No | Yes (authenticator app) |
| Works without phone | Yes (just email access) | No |
| Phishing resistance | Low | Medium |
| User friction | Medium (check email) | Low (app open) |
| Recommended for | General users | Power users, admin accounts |
