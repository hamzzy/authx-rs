---
title: ABAC Policies
description: Attribute-based access control with composable policy rules.
---

authx ships four built-in ABAC policies. Combine them — or write your own — by implementing the `Policy` trait.

## Built-in policies

### OrgBoundaryPolicy

Denies access to resources scoped to an org that doesn't match the user's active org.

```rust
use authx_core::policy::builtin::OrgBoundaryPolicy;

engine.add_policy(OrgBoundaryPolicy);
// Resource format: "org:<org_id>:<resource_name>"
```

### RequireEmailVerifiedPolicy

Denies actions matching a prefix until the user's email is verified.

```rust
use authx_core::policy::builtin::RequireEmailVerifiedPolicy;

// Blocks "admin.*" actions for unverified users
engine.add_policy(RequireEmailVerifiedPolicy::for_prefix("admin."));
```

### IpAllowListPolicy

Permits only requests from listed CIDR ranges.

```rust
use authx_core::policy::builtin::IpAllowListPolicy;

engine.add_policy(IpAllowListPolicy::new(["10.0.0.0/8", "192.168.1.0/24"]));
```

### TimeWindowPolicy

Restricts access to specific hours and/or days.

```rust
use authx_core::policy::builtin::TimeWindowPolicy;

// Weekdays only, 09:00–18:00 UTC
engine.add_policy(TimeWindowPolicy::weekdays(9, 18));
```

## Composing policies

```rust
use authx_core::policy::AuthzEngine;

let mut engine = AuthzEngine::new();
engine.add_policy(OrgBoundaryPolicy);
engine.add_policy(RequireEmailVerifiedPolicy::for_prefix("admin."));
engine.add_policy(IpAllowListPolicy::new(["10.0.0.0/8"]));

engine.enforce("admin.users.delete", &identity, Some("org:acme:users")).await?;
```

Policies are evaluated in order. The first `Deny` wins. `Abstain` passes to the next policy. If all abstain, access is **permitted**.

## Custom policy

```rust
use authx_core::policy::engine::{AuthzContext, Policy, PolicyDecision};
use async_trait::async_trait;

struct PremiumOnlyPolicy;

#[async_trait]
impl Policy for PremiumOnlyPolicy {
    async fn evaluate(&self, action: &str, ctx: &AuthzContext) -> PolicyDecision {
        if action.starts_with("premium.") {
            let is_premium = ctx.identity.user.metadata
                .get("plan")
                .and_then(|v| v.as_str())
                == Some("premium");

            if !is_premium {
                return PolicyDecision::Deny("premium subscription required".into());
            }
        }
        PolicyDecision::Abstain
    }
}

engine.add_policy(PremiumOnlyPolicy);
```
