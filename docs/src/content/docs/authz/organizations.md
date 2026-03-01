---
title: Organizations
description: Multi-tenancy with organizations, roles, memberships, and invitations.
---

import { Aside } from '@astrojs/starlight/components';

authx has first-class multi-tenancy support. Users can belong to multiple organizations simultaneously, switching context per-request via the active org on their session.

## Creating an organization

```rust
use authx_plugins::OrgService;

let svc = OrgService::new(store.clone(), events.clone());

let (org, membership) = svc.create(
    owner_user_id,
    "Acme Corp",   // display name
    "acme",        // slug (unique)
    None,          // optional metadata JSON
).await?;

// org.id          — UUID
// membership.role — "owner" (built-in role, all permissions)
```

## Inviting members

```rust
// Create a role first
let editor_role = svc.create_role(org.id, "editor", vec!["posts.write", "posts.delete"]).await?;

// Invite — returns raw token (you email it yourself)
let details = svc.invite_member(org.id, "bob@example.com", editor_role.id, actor_id).await?;
let link = format!("https://app.example.com/accept-invite?token={}", details.raw_token);
```

## Accepting an invitation

```rust
// When the invitee clicks the link:
let membership = svc.accept_invite(&raw_token, bob_user_id).await?;
// Returns Err(AuthError::InvalidToken) if token is expired or already accepted
```

## Switching active org

A session carries one active org at a time. To switch:

```rust
let updated_session = svc.switch_org(session_id, target_org_id, user_id).await?;
// Returns Err(AuthError::Forbidden) if user is not a member of target_org
```

The new `identity.active_org` is available on the next request after the session is refreshed.

## Removing a member

```rust
svc.remove_member(org_id, user_id, actor_id).await?;
// actor_id is the admin performing the action — for audit logging
```

## Listing members

```rust
let members = svc.list_members(org_id).await?;
// Vec<Membership> — each includes user_id, role_id, joined_at
```

<Aside type="note">
Organization slugs must be globally unique. Duplicate slugs return `Err(AuthError::Storage(StorageError::Conflict(...)))`.
</Aside>
