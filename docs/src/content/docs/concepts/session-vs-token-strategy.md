---
title: Session vs Token Strategy
description: Choosing between cookie-backed sessions and OAuth/OIDC token flows.
---

Use this as your default decision framework.

## Quick recommendation

- **Browser app (same domain/backend)**: use cookie-backed sessions.
- **API clients / mobile / third-party apps**: use OAuth/OIDC tokens.
- **Mixed architecture**: browser uses session cookie, backend services use access tokens.

## Trade-off matrix

| Dimension | Session Cookie | Access/Refresh Tokens |
|---|---|---|
| Best fit | Web apps with first-party backend | APIs, mobile, third-party clients |
| Revocation | Simple (invalidate server row) | Requires token revocation/introspection strategy |
| CSRF | Must protect state-changing routes | Not cookie-bound by default; CSRF lower risk |
| XSS impact | HttpOnly helps protect token theft | If stored in JS storage, higher theft risk |
| Horizontal scale | Needs shared session store | Stateless access tokens scale well |
| UX persistence | `remember_me` controls TTL | Refresh token controls long-lived auth |

## authx defaults

- Session tokens are random opaque values; only SHA-256 hashes are stored server-side.
- Cookies are `HttpOnly`, `SameSite=Lax`, optional `Secure`.
- `remember_me` can use a longer TTL policy than standard sign-in.

## Enterprise pattern

1. Keep user-facing browser auth on sessions.
2. Issue scoped access tokens only where service-to-service or external API access is required.
3. Keep refresh token lifetimes and scopes conservative.
4. Audit admin and token-management operations.
