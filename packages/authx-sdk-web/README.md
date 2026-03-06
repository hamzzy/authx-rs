# @authx-rs/sdk-web

Higher-level browser helpers for `authx-rs` token-based clients.

Current scope:

- token persistence with pluggable storage
- access token expiry tracking
- single-flight refresh orchestration
- authenticated `fetch()` wrapper with optional 401 retry
- OIDC refresh handler for standard token endpoints

The package is ESM-only and targets modern runtimes with `fetch`, `URL`, and timers.

## Example

```ts
import {
  AuthxTokenManager,
  BrowserStorageTokenStore,
  createOidcTokenRefresher,
} from "@authx-rs/sdk-web";

const client = new AuthxTokenManager({
  storage: new BrowserStorageTokenStore(),
  refresh: createOidcTokenRefresher({
    tokenEndpoint: "https://auth.example.com/oidc/token",
    clientId: "spa-client",
  }),
});

await client.start();
await client.setTokenResponse({
  access_token: "access-token",
  token_type: "Bearer",
  expires_in: 3600,
  refresh_token: "refresh-token",
});

const response = await client.fetch("https://api.example.com/me");
```
