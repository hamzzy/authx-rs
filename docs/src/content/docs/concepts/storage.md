---
title: Storage Adapters
description: The repository trait system and how storage works in authx-rs.
---

authx-rs uses a **ports and adapters** (hexagonal) architecture for storage. The core defines _what_ operations exist via traits; adapters define _how_ they're executed.

## Repository traits

| Trait | Responsibility |
|---|---|
| `UserRepository` | CRUD users, find by email/username/id, list paginated |
| `SessionRepository` | Create/invalidate sessions, find by token hash or user |
| `CredentialRepository` | Store/retrieve password hashes, TOTP secrets, passkeys |
| `OrgRepository` | Organizations, roles, memberships |
| `ApiKeyRepository` | API key CRUD, hash lookup, touch last_used_at |
| `OAuthAccountRepository` | Upsert OAuth accounts, find by provider |
| `InviteRepository` | Create/accept/expire org invitations |
| `AuditLogRepository` | Append/query audit log entries |

## StorageAdapter blanket

```rust
pub trait StorageAdapter:
    UserRepository + SessionRepository + CredentialRepository +
    OrgRepository + ApiKeyRepository + OAuthAccountRepository +
    InviteRepository + AuditLogRepository + Send + Sync + 'static
{}

impl<T: UserRepository + SessionRepository + …> StorageAdapter for T {}
```

Implement all traits and your type is automatically a `StorageAdapter` — no extra boilerplate.

## Provided adapters

| Adapter | Use case | Feature flag |
|---|---|---|
| `MemoryStore` | Tests, local dev | (always available) |
| `PostgresStore` | Production | `sqlx-postgres` |

## UFCS requirement

When a type implements multiple traits that share a method name (e.g. both `UserRepository` and `SessionRepository` have `create`), you must use Fully Qualified Syntax:

```rust
// Correct
UserRepository::create(&self.storage, create_user_data).await?;
SessionRepository::create(&self.storage, create_session_data).await?;

// Won't compile — ambiguous
self.storage.create(data).await?;
```
