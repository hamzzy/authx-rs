---
title: Enterprise SSO with OIDC Federation
description: Connect external enterprise IdPs (Okta/Azure AD/Google Workspace) to authx federation.
---

Use this flow when customers bring their own IdP.

## 1. Set encryption key

Configure a shared AES-256 key for federation secret encryption:

```bash
export AUTHX_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```

Both dashboard and CLI federation create flows use this key source.

## 2. Register federation provider

You can use either:

- Dashboard: **OIDC Federation Providers** -> **New Provider**
- CLI:

```bash
authx oidc federation create acme-okta \
  https://acme.okta.com \
  <client_id> \
  <client_secret> \
  --scopes "openid profile email"
```

## 3. Start login

Redirect users to:

`/auth/oidc/federation/:provider/begin?redirect_uri=<callback>`

authx will:

1. Discover provider metadata from issuer.
2. Start authorization request with PKCE + state.
3. Complete callback and issue a local authx session.

## 4. Operational guidance

- One provider per tenant/customer naming convention.
- Enforce issuer allowlists in your provisioning process.
- Rotate external client secrets and re-save via dashboard/CLI.
- Audit who can create/update federation providers.
