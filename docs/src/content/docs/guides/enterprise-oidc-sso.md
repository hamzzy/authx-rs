---
title: Integrate Okta, Azure AD, or Google Workspace via OIDC
description: Configure authx-rs federation providers for enterprise SSO and map upstream identities into local users and organizations.
---

This guide covers authx-rs as the relying party and an upstream enterprise IdP as the identity source.

## 1. Create the upstream OIDC application

In Okta, Azure AD, or Google Workspace, create an OIDC app with:

- authorization code flow enabled
- a redirect URI pointing back to authx-rs:
  `https://auth.example.com/auth/federation/<provider>/callback`
- scopes that include at least `openid`
- `email` and `profile` when you want richer account linking

The redirect URI must be the authx federation callback, not a SPA route.

## 2. Store the provider in authx-rs

Each provider needs:

- `name`: for example `okta`, `azure`, or `google`
- `issuer`: the upstream issuer URL
- `client_id`
- encrypted `client_secret`
- scopes string such as `openid profile email`
- optional `org_id`
- optional claim mapping rules

You can create this record through the dashboard or CLI.

## 3. Mount the federation router

```rust
use std::sync::Arc;

use authx_axum::oidc_federation_router;
use authx_plugins::oidc_federation::OidcFederationService;

let encryption_key: [u8; 32] = /* stable app secret */;

let federation = Arc::new(OidcFederationService::new(
    store.clone(),
    60 * 60 * 24 * 30,
    encryption_key,
));

let app = Router::new()
    .nest("/auth/federation", oidc_federation_router(federation))
    .layer(SessionLayer::new(store));
```

## 4. Start sign-in

Redirect the browser to:

```text
https://auth.example.com/auth/federation/okta/begin
  ?redirect_uri=https://auth.example.com/auth/federation/okta/callback
```

authx-rs performs discovery, generates PKCE, and redirects to the upstream IdP.

## 5. Understand the callback behavior

Today, the built-in callback handler:

- exchanges the code
- fetches userinfo
- creates or updates the local user
- creates a local authx session
- sets the session cookie
- returns JSON with `user_id`, `session_id`, and `token`

If you need a final redirect back to a browser app, add a thin app-specific wrapper handler around `OidcFederationService`.

## 6. Map enterprise identity into tenants

Use claim mappings and `org_id` to control where federated users land:

- auto-join an organization
- assign a default role
- scope a provider to one tenant

This is the piece that turns generic SSO into multi-tenant SaaS behavior.

## Provider-specific notes

- Okta: issuer is usually your Okta authorization server URL.
- Azure AD: issuer and claim shape vary by tenant and app registration mode.
- Google Workspace: prefer a hosted-domain-aware policy or claim mapping strategy if you need tenant scoping.

## Related docs

- [OIDC Federation](/concepts/oidc-federation/)
- [Organizations & Roles](/concepts/organizations-and-roles/)
