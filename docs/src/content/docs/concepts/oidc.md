---
title: OIDC Provider and Federation
description: authx as an OIDC Identity Provider and as an OIDC Federation broker.
---

authx supports two complementary OIDC roles:

- **OIDC Provider (IdP)**: your app delegates login to authx (`/authorize`, `/token`, `/userinfo`, `/jwks`).
- **OIDC Federation**: authx delegates login to external enterprise IdPs (Okta, Azure AD, Google Workspace).

## OIDC Provider model

`OidcClient` records define relying parties:

- `client_id`
- `secret_hash` (empty means public client)
- `redirect_uris`
- `allowed_scopes`

### PKCE policy

- Public clients (**no client secret**) must send `code_challenge` with `S256`.
- Confidential clients may use client secret only, or client secret + PKCE.
- Token exchange validates PKCE whenever the authorization code stores a challenge.

This protects authorization codes from interception/replay, especially for browser/mobile clients.

## Federation model

`OidcFederationProvider` stores external IdP configuration:

- `issuer`
- `client_id`
- `secret_enc` (**encrypted at rest**)
- `scopes`

During callback, authx:

1. Exchanges code at the external token endpoint.
2. Fetches userinfo.
3. Finds or creates a local user.
4. Creates a local authx session.

## Key management

Federation `client_secret` values are encrypted with AES-256-GCM using `AUTHX_ENCRYPTION_KEY` (hex-encoded 32-byte key).

- Dashboard create-provider flow encrypts before storage.
- CLI federation create uses the same key source.

## Related docs

- [Session vs Token Strategy](/concepts/session-vs-token-strategy/)
- [SPA IdP Integration Guide](/guides/spa-idp-integration/)
- [Enterprise SSO Integration Guide](/guides/enterprise-sso-integration/)
