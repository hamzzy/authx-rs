---
title: OIDC Federation
description: Using authx-rs as the relying party for upstream enterprise identity providers.
---

OIDC federation is the inverse of the provider feature: authx-rs delegates login to another identity provider such as Okta, Azure AD, or Google Workspace, then creates a local authx session after the upstream sign-in succeeds.

## What a federation provider record contains

Each upstream IdP is represented by an `OidcFederationProvider` record:

- `name`: local identifier used in routes
- `issuer`: discovery base URL for the upstream IdP
- `client_id`
- encrypted `client_secret`
- requested scopes
- optional `org_id` to scope sign-ins into one tenant
- optional claim-mapping rules

## Runtime flow

1. `/auth/federation/:provider/begin` loads the provider record.
2. authx-rs discovers the upstream OIDC metadata.
3. It creates PKCE state and redirects the browser to the upstream authorization endpoint.
4. The upstream IdP redirects back to `/auth/federation/:provider/callback`.
5. authx-rs exchanges the code, fetches userinfo, upserts the local user/account mapping, applies claim rules, and creates a local session.

## Claim mapping

Claim-mapping rules let upstream identity claims drive local behavior. Current actions include:

- `add_to_org`
- `assign_role`
- `set_attribute`

This is the bridge between enterprise identity data and authx's local tenant model.

## Important current behavior

The built-in Axum federation callback sets the authx session cookie and returns JSON describing the new session. It does not yet perform a final browser redirect back to a SPA route on its own.

If you need a polished browser experience, wrap `OidcFederationService` in an application-specific handler that:

- controls the final post-login redirect
- persists any extra state you need
- converts the JSON callback into a full-page navigation

## Related docs

- [Enterprise OIDC guide](/guides/enterprise-oidc-sso/)
- [SPA integration](/guides/spa-integration/)
