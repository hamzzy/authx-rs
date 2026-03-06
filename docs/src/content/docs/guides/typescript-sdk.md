---
title: TypeScript SDK
description: TypeScript SDK packages for authx-rs browser and server runtimes.
---

The repository now contains a layered TypeScript SDK family under `packages/`:

- `packages/authx-sdk-ts/` for low-level OIDC, JWKS, PKCE, device, and browser-session helpers
- `packages/authx-sdk-web/` for browser token storage and auto-refresh orchestration
- `packages/authx-sdk-react/` for React provider/hooks on top of `@authx/sdk-web`
- `packages/authx-sdk-vue/` for Vue plugin/composable on top of `@authx/sdk-web`

Consumer examples now live in:

- `examples/react-sdk-app/`
- `examples/vue-sdk-app/`

Maintainers should use the dedicated publish guide at `/guides/publish-typescript-sdk/`.

The low-level package is dependency-free and targets modern runtimes with:

- `fetch`
- `URL`
- Web Crypto (`crypto.getRandomValues`, `crypto.subtle`)

## Package split

### `@authx/sdk`

- OIDC discovery
- JWKS fetch and key selection helpers
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

This package is ESM-only and intentionally stays at the protocol/helper layer.

### `@authx/sdk-web`

- token persistence with pluggable storage
- access-token expiry tracking
- single-flight refresh orchestration
- authenticated `fetch()` wrapper with bearer injection
- optional retry after `401`
- OIDC refresh helper for standard token endpoints

### `@authx/sdk-react`

- `AuthxTokenProvider`
- `useAuthxToken`
- `useAuthxSnapshot`
- `useAccessToken`
- `useIsAuthenticated`
- `useAuthenticatedFetch`

### `@authx/sdk-vue`

- `createAuthxPlugin`
- `useAuthxToken`
- reactive token snapshot and access-token state

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

## Browser token manager example

```ts
import {
  AuthxTokenManager,
  BrowserStorageTokenStore,
  createOidcTokenRefresher,
} from "@authx/sdk-web";

const tokens = new AuthxTokenManager({
  storage: new BrowserStorageTokenStore(),
  refresh: createOidcTokenRefresher({
    tokenEndpoint: "https://auth.example.com/oidc/token",
    clientId: "spa-client-id",
  }),
});

await tokens.start();
```

## React example

```tsx
import { AuthxTokenProvider, useIsAuthenticated } from "@authx/sdk-react";

function AuthState() {
  const isAuthenticated = useIsAuthenticated();
  return <div>{isAuthenticated ? "signed-in" : "signed-out"}</div>;
}

<AuthxTokenProvider client={tokens}>
  <AuthState />
</AuthxTokenProvider>;
```

## Vue example

```ts
import { createAuthxPlugin, useAuthxToken } from "@authx/sdk-vue";

app.use(createAuthxPlugin(tokens));

const auth = useAuthxToken();
console.log(auth.isAuthenticated.value);
```

## Verification and current limitations

- `@authx/sdk`, `@authx/sdk-web`, `@authx/sdk-react`, and `@authx/sdk-vue` all build in this repo
- `@authx/sdk-web` has runtime tests for token refresh and storage behavior
- `@authx/sdk-react` has runtime tests against a real React runtime
- `@authx/sdk-vue` has runtime tests against a real Vue runtime
- generated API reference lives under `/reference/typescript/`
- tag-driven npm publishing is configured in `.github/workflows/release.yml`
- JS version PRs are prepared by `.github/workflows/js-versioning.yml`
- actual npm publication still requires a release tag and `NPM_TOKEN`
