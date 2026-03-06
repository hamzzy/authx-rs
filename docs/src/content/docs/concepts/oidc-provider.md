---
title: OIDC Provider
description: authx-rs as an OpenID Connect provider and OAuth 2.0 authorization server.
---

The OIDC provider side of authx-rs lets your application act as the identity provider for other apps, SPAs, CLIs, and services.

## What it exposes

The Axum integration provides standard endpoints under the OIDC router:

- discovery: `/.well-known/openid-configuration`
- authorization: `/authorize`
- token: `/token`
- userinfo: `/userinfo`
- JWKS: `/jwks`
- introspection: `/introspect`
- revocation: `/revoke`
- device authorization: `/device_authorization`

## Supported flows

### Authorization code

For browser and server-side clients. Public clients can use PKCE; confidential clients can use a client secret.

### Refresh token

Longer-lived refresh tokens can mint new access tokens without forcing the user through another login.

### Device authorization

For CLIs and input-constrained devices. authx-rs issues a device code and user code, then the user completes verification in a browser session.

## Storage model

The provider uses dedicated repository traits for:

- registered OIDC clients
- authorization codes
- OIDC tokens
- device codes

That keeps the protocol logic in `authx-plugins` while allowing different backends in `authx-storage`.

## Security model

- client secrets are stored hashed, not raw
- authorization codes are single-use and short-lived
- PKCE is supported for public clients
- access tokens are JWTs signed through `KeyRotationStore`
- refresh tokens are opaque and stored hashed

## When to use it

Use authx-rs as an OIDC provider when:

- you want your own apps to trust a central authx deployment
- you need standard OAuth/OIDC interoperability instead of custom session APIs
- you want device-code support for CLI or TV-style clients

## Related docs

- [Use authx-rs as an IdP for your SPA](/guides/authx-idp-for-spa/)
- [Session vs Token Strategy](/concepts/session-vs-token/)
