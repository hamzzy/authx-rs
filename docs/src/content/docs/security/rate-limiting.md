---
title: Rate Limiting
description: Per-IP sliding window rate limiting for authentication endpoints.
---

authx provides a Tower `Layer` that enforces per-IP rate limits using an in-memory sliding window counter.

## Setup

```rust
use authx_axum::{RateLimitLayer, RateLimitConfig};
use std::time::Duration;

let rate_limit = RateLimitLayer::new(
    RateLimitConfig::new(
        20,                       // max requests
        Duration::from_secs(60),  // per rolling window
    )
);

// Apply to auth routes only (recommended)
let auth_router = Router::new()
    .nest("/auth", auth_handlers)
    .layer(rate_limit);
```

## How it works

1. Each incoming request extracts the client IP from (in order): `X-Forwarded-For`, `X-Real-IP`, or the direct socket address.
2. A counter for that IP is incremented and checked against the window.
3. Requests exceeding the limit receive `429 Too Many Requests` immediately — no forwarding to handlers.
4. Counters expire automatically when the window slides past their last request timestamp.

## IP extraction priority

```
X-Forwarded-For (first IP in the list)
  → X-Real-IP
    → socket peer address
```

If your app runs behind a load balancer or reverse proxy, ensure it sets `X-Forwarded-For` correctly.

## Configuration examples

```rust
// Strict: 10 requests per minute (login page)
RateLimitConfig::new(10, Duration::from_secs(60))

// Relaxed: 100 requests per minute (API)
RateLimitConfig::new(100, Duration::from_secs(60))

// Very strict: 5 requests per 5 minutes (password reset)
RateLimitConfig::new(5, Duration::from_secs(300))
```

## Combining with brute-force lockout

Rate limiting and lockout are complementary:

| | Rate limiting | Brute-force lockout |
|---|---|---|
| Scope | Per-IP | Per-account |
| Resets | Sliding window | After window expires |
| Response | 429 (no account touched) | 429 (account locked flag set) |
| Bypass | Change IP | Cannot bypass — account locked |
