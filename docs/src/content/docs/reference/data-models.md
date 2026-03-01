---
title: Data Models
description: All core data structures in authx-rs.
---

## User

```rust
pub struct User {
    pub id:             Uuid,
    pub email:          String,
    pub email_verified: bool,
    pub username:       Option<String>,
    pub created_at:     DateTime<Utc>,
    pub updated_at:     DateTime<Utc>,
    pub metadata:       serde_json::Value,
}
```

## Session

```rust
pub struct Session {
    pub id:          Uuid,
    pub user_id:     Uuid,
    pub token_hash:  String,
    pub device_info: serde_json::Value,
    pub ip_address:  String,
    pub org_id:      Option<Uuid>,
    pub expires_at:  DateTime<Utc>,
    pub created_at:  DateTime<Utc>,
}
```

## Credential

```rust
pub struct Credential {
    pub id:              Uuid,
    pub user_id:         Uuid,
    pub kind:            CredentialKind,
    pub credential_hash: String,
    pub metadata:        Option<serde_json::Value>,
    pub created_at:      DateTime<Utc>,
    pub updated_at:      DateTime<Utc>,
}

pub enum CredentialKind {
    Password,
    Passkey,
    Totp,
}
```

## Organization

```rust
pub struct Organization {
    pub id:         Uuid,
    pub name:       String,
    pub slug:       String,
    pub metadata:   serde_json::Value,
    pub created_at: DateTime<Utc>,
}

pub struct Role {
    pub id:          Uuid,
    pub org_id:      Uuid,
    pub name:        String,
    pub permissions: Vec<String>,
    pub created_at:  DateTime<Utc>,
}

pub struct Membership {
    pub id:         Uuid,
    pub org_id:     Uuid,
    pub user_id:    Uuid,
    pub role_id:    Uuid,
    pub created_at: DateTime<Utc>,
}
```

## ApiKey

```rust
pub struct ApiKey {
    pub id:           Uuid,
    pub user_id:      Uuid,
    pub org_id:       Option<Uuid>,
    pub key_hash:     String,
    pub prefix:       String,    // first 8 chars of raw key
    pub name:         String,
    pub scopes:       Vec<String>,
    pub expires_at:   Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}
```

## AuditLog

```rust
pub struct AuditLog {
    pub id:            Uuid,
    pub user_id:       Option<Uuid>,
    pub org_id:        Option<Uuid>,
    pub action:        String,
    pub resource_type: String,
    pub resource_id:   Option<String>,
    pub ip_address:    Option<String>,
    pub metadata:      serde_json::Value,
    pub created_at:    DateTime<Utc>,
}
```

## Invite

```rust
pub struct Invite {
    pub id:          Uuid,
    pub org_id:      Uuid,
    pub email:       String,
    pub role_id:     Uuid,
    pub token_hash:  String,
    pub expires_at:  DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}
```

## OAuthAccount

```rust
pub struct OAuthAccount {
    pub id:                Uuid,
    pub user_id:           Uuid,
    pub provider:          String,
    pub provider_user_id:  String,
    pub access_token_enc:  String,   // AES-256-GCM encrypted
    pub refresh_token_enc: Option<String>,
    pub expires_at:        Option<DateTime<Utc>>,
}
```
