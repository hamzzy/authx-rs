---
title: TOTP Setup
description: Time-based one-time passwords (Google Authenticator, Authy, 1Password).
---

import { Aside, Steps } from '@astrojs/starlight/components';

The `TotpService` implements RFC 6238 TOTP compatible with any authenticator app.

## Setup

```rust
use authx_plugins::TotpService;

let svc = TotpService::new(store.clone(), "MyApp"); // issuer name shown in authenticator
```

## Enrollment flow

<Steps>

1. **Begin setup** — generates a secret and QR code URI

   ```rust
   let setup = svc.begin_setup(user_id).await?;

   setup.secret_base32   // base32 secret (show to user as fallback)
   setup.otpauth_uri     // otpauth:// URI → render as QR code
   setup.backup_codes    // 8 single-use recovery codes — show once, store hashed
   ```

2. **Render the QR code** using any QR library (e.g. `qrcode` crate)

   ```rust
   use qrcode::QrCode;
   let code = QrCode::new(setup.otpauth_uri.as_bytes()).unwrap();
   ```

3. **User scans** the QR code in their authenticator app

4. **Confirm setup** — user provides the first code to prove they enrolled correctly

   ```rust
   svc.confirm_setup(user_id, &setup, "123456").await?;
   // Returns Err(AuthError::InvalidToken) if code doesn't match
   // On success, persists the TOTP credential
   ```

</Steps>

## Verify on sign-in

```rust
use authx_plugins::TotpVerifyRequest;

svc.verify(TotpVerifyRequest {
    user_id,
    code: "123456".into(),
}).await?;
// Works with both TOTP codes and backup codes
```

## Check enrollment status

```rust
let enrolled = svc.is_enabled(user_id).await?;
```

## Disable TOTP

```rust
svc.disable(user_id).await?;
```

<Aside type="tip">
Always show backup codes immediately after enrollment and prompt users to store them securely. They cannot be retrieved later.
</Aside>
