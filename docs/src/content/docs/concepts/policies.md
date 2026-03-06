---
title: Policies
description: How the authx-rs policy engine complements roles with contextual authorization rules.
---

Roles answer "what can this member usually do?" Policies answer "is this specific request allowed right now?"

In authx-rs, policies live in `authx-core` and are evaluated by `AuthzEngine`. They operate on the current `Identity`, an action string, and optional resource/context information.

## Why policies exist

RBAC alone is not enough for real systems. You often need rules like:

- deny access outside the active organization
- require verified email for admin actions
- restrict certain actions to corporate IP ranges
- limit privileged operations to a time window
- require MFA for sensitive routes

Those rules are contextual. They are better expressed as policies than as role names.

## Evaluation model

Each policy returns one of three outcomes:

- `Allow`
- `Deny`
- `Abstain`

The important behavior is:

- first `Deny` wins
- `Abstain` passes evaluation to the next policy
- if every policy abstains, the request is allowed

That means policies are best used for explicit safety rails and context checks, not as a second role system.

## Built-in policy examples

authx-rs includes policies such as:

- `OrgBoundaryPolicy`
- `RequireEmailVerifiedPolicy`
- `IpAllowListPolicy`
- `TimeWindowPolicy`

Typical composition:

```rust
use authx_core::policy::{AuthzEngine, builtin::*};

let mut engine = AuthzEngine::new();
engine.add_policy(OrgBoundaryPolicy);
engine.add_policy(RequireEmailVerifiedPolicy::for_prefix("admin."));
engine.add_policy(IpAllowListPolicy::new(["10.0.0.0/8"]));
```

## Roles vs policies

| Concern | Best tool |
|---|---|
| "Editors can update posts" | Role permission |
| "Only within the active org" | Policy |
| "Only from corporate IPs" | Policy |
| "Only verified accounts may do admin work" | Policy |
| "Billing admins can export invoices" | Role permission |

## Where to enforce

Keep policies close to the boundary where the decision matters:

- HTTP handlers for request-level authorization
- service methods for domain invariants that must hold regardless of transport

## Related docs

- [ABAC](/authz/abac/)
- [Organizations & Roles](/concepts/organizations-and-roles/)
