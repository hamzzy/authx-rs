---
title: Brute Force Protection
description: Account-level lockout after repeated failed sign-in attempts.
---

authx tracks failed sign-in attempts per account and locks accounts that exceed the threshold.

## Configuration

```rust
use authx_core::brute_force::LockoutConfig;
use authx_plugins::EmailPasswordService;
use std::time::Duration;

let lockout = LockoutConfig::new(
    5,                             // max failures before lockout
    Duration::from_secs(15 * 60), // sliding window (15 minutes)
);

let svc = EmailPasswordService::new(store, events, session_ttl)
    .with_lockout(lockout);
```

## How it works

1. On each failed `sign_in`, the failure counter for that account is incremented.
2. Counters use a **sliding window** — failures older than the window are discarded.
3. Once failures reach `max_failures`, the account is locked and `AuthError::AccountLocked` is returned (HTTP 429).
4. The lock lifts automatically once the window has passed with no new failures.
5. A **successful** sign-in resets the counter immediately.

## Responding to lockout

```rust
match svc.sign_in(email, password, ip).await {
    Ok(resp)                              => { /* success */ }
    Err(AuthError::InvalidCredentials)    => { /* wrong password — show generic error */ }
    Err(AuthError::AccountLocked)         => { /* show lockout message + retry-after time */ }
    Err(e)                                => { /* other errors */ }
}
```

## Without lockout

If no `LockoutConfig` is set, `EmailPasswordService` will never lock accounts. This is appropriate for development but should not be used in production.

```rust
// No lockout — development only
let svc = EmailPasswordService::new(store, events, 3600);
```
