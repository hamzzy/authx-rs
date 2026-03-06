---
title: TypeScript SDK
description: Initial TypeScript SDK scaffold for authx-rs browser and server runtimes.
---

An initial SDK scaffold now lives in the repository under `packages/authx-sdk-ts/`.

The package is dependency-free and targets modern runtimes with:

- `fetch`
- `URL`
- Web Crypto (`crypto.getRandomValues`, `crypto.subtle`)

## Current surface area

- OIDC discovery
- PKCE helpers
- authorization URL construction
- code exchange
- refresh token flow
- token revocation
- introspection
- userinfo fetch
- device authorization
- browser-session helpers for authx cookie flows
- typed SDK errors

## PKCE example

```ts
import {
  buildAuthorizationUrl,
  createPkcePair,
  discoverIssuer,
  randomState,
} from "@authx/sdk";

const discovery = await discoverIssuer("https://auth.example.com/oidc");
const pkce = await createPkcePair();
const state = randomState();

const authorizationUrl = buildAuthorizationUrl({
  authorizationEndpoint: discovery.authorization_endpoint,
  clientId: "spa-client-id",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile email",
  state,
  codeChallenge: pkce.codeChallenge,
});
```

## Browser session helper example

```ts
import { BrowserSessionClient } from "@authx/sdk";

const auth = new BrowserSessionClient({
  baseUrl: "https://api.example.com",
});

await auth.signIn({
  email: "alice@example.com",
  password: "hunter2hunter2",
});

const session = await auth.session();
```

## Current limitations

- no published npm package yet
- no generated API docs yet
- no framework-specific React/Vue wrappers yet
- no build/test pipeline in this repo for the package yet

This is a starting point for the roadmap item, not the finished SDK.
