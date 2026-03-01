---
title: Plugins
description: How the authx-rs plugin system works.
---

Every auth feature in authx-rs is a **plugin** — a struct that wraps a storage adapter and an event bus, and exposes a focused API.

## Anatomy of a plugin

```rust
pub struct EmailPasswordService<S> {
    storage:          S,
    events:           EventBus,
    session_ttl_secs: i64,
    lockout:          Option<(LoginAttemptTracker, LockoutConfig)>,
}

impl<S> EmailPasswordService<S>
where
    S: UserRepository + SessionRepository + CredentialRepository
       + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self { … }

    pub async fn sign_up(&self, email: &str, password: &str) -> Result<User> { … }
    pub async fn sign_in(&self, email: &str, password: &str, ip: &str) -> Result<AuthResponse> { … }
    pub async fn sign_out(&self, raw_token: &str) -> Result<()> { … }
}
```

## Plugin design rules

1. **Plugins own no state beyond storage + events.** All persistence goes through the repository layer.
2. **Plugins emit events** — they never write audit logs directly. `AuditLogger` subscribes to the event bus and handles persistence.
3. **Plugins enforce business rules** (weak password, duplicate email, lockout) — storage handles persistence.
4. **No plugin depends on another plugin.** `EmailPasswordService` doesn't import `AdminService`. Cross-cutting concerns use the shared repository layer.

## Available plugins

| Plugin | Service | Key methods |
|---|---|---|
| Email/Password | `EmailPasswordService` | `sign_up`, `sign_in`, `sign_out`, `sign_out_all` |
| Magic Link | `MagicLinkService` | `request_link`, `verify` |
| Email OTP | `EmailOtpService` | `issue`, `verify` |
| TOTP | `TotpService` | `begin_setup`, `confirm_setup`, `verify`, `disable` |
| Password Reset | `PasswordResetService` | `request_reset`, `reset_password` |
| Email Verification | `EmailVerificationService` | `issue`, `verify` |
| OAuth (Social) | `OAuthService` | `begin`, `callback` |
| API Keys | `ApiKeyService` | `create`, `list`, `revoke`, `authenticate` |
| Username Login | `UsernameService` | `sign_up`, `sign_in` |
| Anonymous Auth | `AnonymousService` | `create_guest`, `upgrade` |
| Organization | `OrgService` | `create`, `invite_member`, `accept_invite`, `switch_org` |
| Admin | `AdminService` | `ban_user`, `unban_user`, `impersonate`, `list_users` |
