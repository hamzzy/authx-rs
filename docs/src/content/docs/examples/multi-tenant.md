---
title: Multi-Tenant SaaS
description: Building a multi-tenant SaaS app with organizations, roles, and invitations.
---

This example shows the full organization lifecycle — from creating a workspace to inviting team members with scoped roles.

## Setup

```rust
use authx_plugins::{EmailPasswordService, OrgService};
use authx_storage::memory::MemoryStore;
use authx_core::events::EventBus;

let store  = MemoryStore::new();
let events = EventBus::new();

let auth_svc = EmailPasswordService::new(store.clone(), events.clone(), 86400);
let org_svc  = OrgService::new(store.clone(), events.clone());
```

## 1. Register the owner

```rust
let owner = auth_svc.sign_up("alice@acme.com", "secretpassword").await?;
```

## 2. Create an organization

```rust
let (org, owner_membership) = org_svc.create(
    owner.id,
    "Acme Corp",
    "acme",
    Some(serde_json::json!({ "plan": "pro" })),
).await?;

// owner_membership.role_name == "owner"
```

## 3. Create a custom role

```rust
let editor_role = org_svc.create_role(
    org.id,
    "editor",
    vec!["posts.create", "posts.edit", "posts.publish"],
).await?;
```

## 4. Invite a team member

```rust
// Returns raw token — you email it to bob@acme.com yourself
let invite = org_svc.invite_member(
    org.id,
    "bob@acme.com",
    editor_role.id,
    owner.id,
).await?;

let invite_link = format!(
    "https://app.acme.com/accept-invite?token={}",
    invite.raw_token
);
```

## 5. Bob registers and accepts the invite

```rust
// Bob creates an account
let bob = auth_svc.sign_up("bob@acme.com", "bobpassword").await?;

// Bob accepts the invite
let membership = org_svc.accept_invite(&invite.raw_token, bob.id).await?;
// membership.role_name == "editor"
```

## 6. Bob switches to the org context

```rust
let bob_session = auth_svc.sign_in("bob@acme.com", "bobpassword", "10.0.0.1").await?;
let updated     = org_svc.switch_org(bob_session.session.id, org.id, bob.id).await?;
// Next request: identity.active_org == Some(org)
```

## 7. Enforce authorization

```rust
use authx_core::policy::{AuthzEngine, builtin::OrgBoundaryPolicy};

let mut engine = AuthzEngine::new();
engine.add_policy(OrgBoundaryPolicy);

// In a handler (bob's identity, resource scoped to acme org)
engine.enforce(
    "posts.publish",
    &bob_identity,
    Some(&format!("org:{}:posts", org.id)),
).await?;
```
