---
title: Backup Codes
description: Single-use recovery codes for when a user loses their authenticator.
---

Backup codes are automatically generated during TOTP enrollment. Each code is a one-time-use recovery mechanism — using one marks it consumed and it cannot be reused.

## How they work

During `begin_setup`, `TotpService` generates 8 random backup codes:

```rust
let setup = svc.begin_setup(user_id).await?;
let codes = setup.backup_codes; // Vec<String>, e.g. ["A3K9-MXPW", …]
```

These codes are:
- **Shown once** — display them immediately and prompt the user to save them
- **Stored as SHA-256 hashes** — the raw codes are never persisted
- **Single-use** — once a code is used to sign in, it is invalidated

## Using a backup code

The `TotpService::verify` endpoint accepts backup codes transparently:

```rust
svc.verify(TotpVerifyRequest {
    user_id,
    code: "A3K9-MXPW".into(), // backup code instead of TOTP
}).await?;
```

authx checks TOTP first, then backup codes. The consumed code is removed atomically.

## Regenerating codes

If a user runs low or suspects compromise, generate a fresh set by disabling and re-enabling TOTP:

```rust
svc.disable(user_id).await?;
let setup = svc.begin_setup(user_id).await?;
// new setup.backup_codes — show to user again
svc.confirm_setup(user_id, &setup, &current_totp_code).await?;
```
