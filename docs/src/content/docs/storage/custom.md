---
title: Custom Adapter
description: Implement your own storage backend by implementing the repository traits.
---

Any type that implements all repository traits automatically satisfies `StorageAdapter` via the blanket impl.

## The traits to implement

```rust
use authx_storage::ports::{
    UserRepository,
    SessionRepository,
    CredentialRepository,
    OrgRepository,
    ApiKeyRepository,
    OAuthAccountRepository,
    InviteRepository,
    AuditLogRepository,
};
```

## Minimal example (SQLite via sqlx)

```rust
use async_trait::async_trait;
use authx_core::{error::Result, models::*};
use authx_storage::ports::UserRepository;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct SqliteStore { pool: SqlitePool }

#[async_trait]
impl UserRepository for SqliteStore {
    async fn create(&self, data: CreateUser) -> Result<User> {
        let id = uuid::Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (id, email, email_verified, username, metadata, created_at, updated_at)
             VALUES (?, ?, false, ?, '{}', datetime('now'), datetime('now'))",
            id.to_string(), data.email, data.username
        )
        .execute(&self.pool)
        .await
        .map_err(|e| authx_core::error::AuthError::Storage(
            authx_core::error::StorageError::Database(e.to_string())
        ))?;

        self.find_by_id(id).await?.ok_or(
            authx_core::error::AuthError::Internal("insert succeeded but find failed".into())
        )
    }

    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<User>> {
        // … query implementation
        todo!()
    }

    // … implement all other methods
}

// Implement all remaining repository traits…
// Then StorageAdapter is satisfied automatically — no extra impl needed.
```

## Error mapping

Convert your database errors to `AuthError`:

```rust
fn map_db_err(e: sqlx::Error) -> AuthError {
    match e {
        sqlx::Error::RowNotFound => AuthError::Storage(StorageError::NotFound),
        sqlx::Error::Database(ref db) if db.is_unique_violation() => {
            AuthError::Storage(StorageError::Conflict(e.to_string()))
        }
        other => AuthError::Storage(StorageError::Database(other.to_string())),
    }
}
```

## Testing your adapter

Use the same test patterns as `MemoryStore` — all repository contracts are tested identically:

```rust
#[tokio::test]
async fn create_and_find_user() {
    let store = MyCustomStore::connect("…").await.unwrap();
    let user  = UserRepository::create(&store, CreateUser {
        email: "test@example.com".into(), username: None, metadata: None,
    }).await.unwrap();

    let found = UserRepository::find_by_id(&store, user.id).await.unwrap();
    assert_eq!(found.unwrap().email, "test@example.com");
}
```
