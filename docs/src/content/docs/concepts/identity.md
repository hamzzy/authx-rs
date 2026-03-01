---
title: Identity
description: The Identity type — the resolved, request-scoped user context.
---

`Identity` is the central type available in handlers after `SessionLayer` runs. It represents the fully resolved, authenticated user for the current request.

## Structure

```rust
pub struct Identity {
    pub user:               User,
    pub session:            Session,
    pub active_org:         Option<Organization>,
    pub active_membership:  Option<Membership>,
}
```

## Accessing Identity in Axum

```rust
use authx_axum::RequireAuth;

async fn handler(RequireAuth(identity): RequireAuth) -> impl IntoResponse {
    let user   = &identity.user;
    let org    = identity.active_org.as_ref();
    let member = identity.active_membership.as_ref();

    Json(serde_json::json!({
        "user_id":     user.id,
        "email":       user.email,
        "verified":    user.email_verified,
        "active_org":  org.map(|o| o.name.as_str()),
        "role":        member.map(|m| m.role_id.to_string()),
    }))
}
```

## Optional identity

To access identity without requiring authentication (e.g. for routes that behave differently when signed in):

```rust
use axum::extract::Extension;
use authx_core::identity::Identity;

async fn maybe_authed(
    identity: Option<Extension<Identity>>,
) -> impl IntoResponse {
    if let Some(Extension(id)) = identity {
        Json(serde_json::json!({ "signed_in": true, "email": id.user.email }))
    } else {
        Json(serde_json::json!({ "signed_in": false }))
    }
}
```

## User metadata

`user.metadata` is an untyped `serde_json::Value`. authx uses it internally for features like guest flags and ban reasons. You can store your own data here:

```rust
// Read
let plan = user.metadata.get("plan").and_then(|v| v.as_str());

// Write (via UpdateUser)
UserRepository::update(&store, user_id, UpdateUser {
    metadata: Some(serde_json::json!({ "plan": "premium", "seats": 10 })),
    ..Default::default()
}).await?;
```
