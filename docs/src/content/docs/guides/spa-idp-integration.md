---
title: Use authx as IdP for a SPA
description: Integrate a single-page app with authx OIDC Provider using Authorization Code + PKCE.
---

This guide covers SPA login against authx as the Identity Provider.

## Prerequisites

- OIDC client created with your SPA callback URL.
- For SPA/public clients, do **not** set a client secret.
- Your SPA must send PKCE `code_challenge` (`S256`) on `/authorize`.

## Flow

1. SPA generates `code_verifier` and `code_challenge`.
2. SPA redirects user to authx `/authorize` with:
   - `response_type=code`
   - `client_id`
   - `redirect_uri`
   - `scope=openid profile email`
   - `state`
   - `code_challenge`
   - `code_challenge_method=S256`
3. authx redirects back with `code`.
4. SPA exchanges code at `/token` with `code_verifier`.
5. SPA uses `access_token` for API calls and `id_token` for identity claims.

## Security checks

- Validate `state` on callback.
- Keep `code_verifier` only in short-lived memory/session storage.
- Validate ID token issuer/audience/expiry in the SPA backend or BFF layer.
- Use short access-token TTL and controlled refresh-token rotation.

## Note

authx enforces PKCE for public clients. Missing `code_challenge` or wrong `code_challenge_method` is rejected.
