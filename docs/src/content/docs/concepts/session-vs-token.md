---
title: Session vs Token Strategy
description: Decision matrix for choosing between session-based auth, JWT tokens, and device authorization in authx-rs.
---

## Session-based auth (cookies)

authx-rs generates a 32-byte random token on sign-in, stores its **SHA-256 hash** in the database, and sends the raw token to the client as an `HttpOnly` cookie (`authx_session`). On each request the middleware re-hashes the cookie value and looks it up in the sessions table. Sign-out deletes the row and clears the cookie.

**Best for:** browser-based SPAs, server-rendered applications.

| Pros | Cons |
|---|---|
| Automatic CSRF protection via `SameSite=Lax` | Not suitable for mobile apps or CLI tools |
| No token management required in JavaScript | Requires browser cookie support |
| Instant server-side revocation (delete the row) | Tied to a single origin by default |
| Raw token never stored — only the hash | Stateful; every request hits the session store |

## Token-based auth (JWT access + refresh)

The authx-rs OIDC provider issues short-lived **JWT access tokens** and longer-lived **opaque refresh tokens**. Access tokens are verified statelessly using the provider's JWKS endpoint. Refresh tokens are stored hashed in the database and support rotation — each use issues a new pair and invalidates the old refresh token.

**Best for:** mobile apps, CLI tools, API-to-API communication, microservices.

| Pros | Cons |
|---|---|
| Stateless verification at resource servers | Harder to revoke before expiry (use introspection) |
| Works across domains and platforms | Client is responsible for secure token storage |
| Suitable for machine-to-machine flows | Access token payload is readable by anyone with the token |
| Standard OIDC/OAuth2 interoperability | Requires refresh-token rotation logic on the client |

## Device Authorization Grant

For **input-constrained devices** — smart TVs, IoT hardware, CLI tools — authx-rs supports the OAuth 2.0 Device Authorization Grant (RFC 8628). The device displays a user code and polls for completion while the user authenticates on a separate device (phone or laptop) by visiting a verification URL and entering the code.

**Best for:** devices without a browser or with limited input capability.

## Decision matrix

| Use case | Recommended approach | Why |
|---|---|---|
| Browser SPA | Session (cookie) | HttpOnly cookie eliminates token-theft via XSS; SameSite handles CSRF |
| Server-rendered web app | Session (cookie) | Same benefits; cookie sent automatically on every request |
| Mobile app | JWT access + refresh tokens | No cookie jar; tokens stored in platform secure storage |
| CLI tool | Device authorization grant | No browser on the device; user authenticates elsewhere |
| Microservice-to-microservice | JWT with client credentials | Stateless verification; no user interaction needed |
| Enterprise SSO | Session via federation callback | OIDC/SAML federation resolves to a local session after the callback |

## Threat model notes

### XSS (Cross-Site Scripting)

Sessions are safer. The `HttpOnly` flag prevents JavaScript from reading the `authx_session` cookie, so a successful XSS attack cannot exfiltrate the session token. JWT tokens stored in `localStorage` or accessible memory can be stolen.

### CSRF (Cross-Site Request Forgery)

Mitigated for sessions by `SameSite=Lax` and the configurable trusted-origins list. Token-based flows are inherently immune to CSRF because the token must be explicitly attached to each request.

### Token theft

JWT access tokens are short-lived (minutes). If stolen, the blast radius is limited to their TTL. Refresh tokens use **rotation** — each use invalidates the previous token, so a stolen refresh token is detected on the next legitimate refresh attempt.

### Revocation

- **Sessions:** instant. Delete the session row and the next request is rejected.
- **JWT access tokens:** cannot be revoked before expiry without contacting the authorization server. Use the `/introspect` endpoint at resource servers that need real-time revocation checks.
- **Refresh tokens:** revoked immediately by deleting or marking the token row in the database.
