---
title: Architecture
description: How the authx-rs crates fit together.
---

## Layered design

```
┌─────────────────────────────────────────────────────┐
│            authx-axum  (HTTP adapter)                │
│  SessionLayer · RateLimitLayer · CSRF · Handlers    │
│  RequireAuth extractor · Cookie helpers             │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│          authx-plugins  (Feature plugins)            │
│  EmailPassword · MagicLink · EmailOTP · TOTP        │
│  PasswordReset · OAuth · ApiKey · Anonymous         │
│  Username · EmailVerification · Organization        │
│  Admin · OneTimeTokenStore · RedisTokenStore        │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│          authx-core  (Zero-dep engine)               │
│  Models · Crypto (Argon2id, AES-GCM, EdDSA)        │
│  RBAC / ABAC policy engine · EventBus               │
│  Identity · Brute-force tracker · Key rotation      │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│         authx-storage  (Repository layer)            │
│  Trait definitions (ports) · MemoryStore            │
│  PostgresStore (sqlx) · AuditLogger                 │
│  StorageAdapter blanket impl                        │
└─────────────────────────────────────────────────────┘
```

## Dependency rules

| Crate | May import |
|---|---|
| `authx-core` | `std`, `serde`, `uuid`, `chrono`, `thiserror`, crypto crates |
| `authx-storage` | `authx-core` + `sqlx` (optional, behind feature flag) |
| `authx-plugins` | `authx-core` + `authx-storage` + `tokio`, `rand`, `argon2`, … |
| `authx-axum` | all above + `axum`, `tower`, `cookie`, `http` |
| `authx-dashboard` | all above |
| `authx-cli` | all above + `clap` |

`authx-core` **never** imports from any HTTP framework. This makes it trivially portable to Actix, any future framework, or a non-HTTP service.

## The StorageAdapter blanket

Every repository is a separate trait:

```rust
pub trait UserRepository    { async fn create(...); async fn find_by_id(...); … }
pub trait SessionRepository { async fn create(...); async fn invalidate(...); … }
pub trait CredentialRepository { … }
// … and so on
```

`StorageAdapter` is a supertrait alias:

```rust
pub trait StorageAdapter:
    UserRepository + SessionRepository + CredentialRepository +
    OrgRepository + ApiKeyRepository + OAuthAccountRepository +
    InviteRepository + AuditLogRepository
{}

// Any T implementing all traits gets StorageAdapter automatically
impl<T: UserRepository + SessionRepository + …> StorageAdapter for T {}
```

This means you can pass any conforming store to any plugin without a type parameter explosion.

## UFCS disambiguation

Both `UserRepository` and `SessionRepository` define a `create` method. When a plugin uses both, Rust requires Fully Qualified Syntax (UFCS):

```rust
// ✅ Correct — unambiguous
UserRepository::create(&self.storage, create_user).await?;
SessionRepository::create(&self.storage, create_session).await?;

// ❌ Ambiguous — won't compile
self.storage.create(create_user).await?;
```

All authx plugins follow this convention.

## Event system

`EventBus` is a `tokio::sync::broadcast` channel. Plugins emit typed `AuthEvent` variants; subscribers (like `AuditLogger`) react asynchronously:

```rust
self.events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });
```

The bus is cloneable and cheaply shareable. Missing events on a lagged subscriber is logged as a warning — it never panics.

## Next reads

- [OIDC Provider and Federation](/concepts/oidc/)
- [Session vs Token Strategy](/concepts/session-vs-token-strategy/)
