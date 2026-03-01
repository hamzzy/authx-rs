---
title: RBAC
description: Role-based access control via organizations and memberships.
---

authx implements RBAC through **Organizations**, **Roles**, and **Memberships**. Every user can belong to multiple organizations, each with a different role.

## Data model

```
Organization
  └─ Role (name, permissions: Vec<String>)
       └─ Membership (user_id, org_id, role_id)
```

## Checking a role in a handler

```rust
use authx_axum::RequireRole;

// Handler only reachable by users with "admin" role in the active org
async fn admin_panel(
    RequireRole(identity, _): RequireRole<"admin">,
) -> impl IntoResponse {
    // identity.active_membership.unwrap().role is verified
}
```

## Programmatic check

```rust
use authx_core::policy::{AuthzEngine, AuthzRequest};

let engine = AuthzEngine::new(); // add policies as needed

engine.enforce(
    "reports.delete",
    &identity,
    Some("org:acme-uuid:reports"),
).await?;
// Returns Err(AuthError::Forbidden) if denied
```

## Managing roles with OrgService

```rust
use authx_plugins::OrgService;

let svc = OrgService::new(store.clone(), events.clone());

// Create organization — owner gets a built-in "owner" role automatically
let (org, membership) = svc.create(owner_id, "Acme Corp", "acme", None).await?;

// Create a custom role
let role = svc.create_role(org.id, "billing", vec!["invoices.read", "invoices.write"]).await?;

// Assign role to a member
svc.set_member_role(org.id, user_id, role.id).await?;

// Invite someone (returns raw token — send it via email yourself)
let details = svc.invite_member(org.id, "bob@example.com", role.id, actor_id).await?;

// Accept invite (user clicks link with token)
let membership = svc.accept_invite(&details.raw_token, new_user_id).await?;
```
