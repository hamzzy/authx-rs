# vue-sdk-app

Minimal Vue consumer example for the authx TypeScript SDK packages.

It demonstrates:

- `@authx-rs/sdk` for OIDC discovery, PKCE, and code exchange
- `@authx-rs/sdk-web` for browser token storage and refresh orchestration
- `@authx-rs/sdk-vue` for plugin/composable integration

## Run

```bash
npm install
npm run dev
```

## Required environment

Create `.env.local`:

```bash
VITE_AUTHX_ISSUER=https://auth.example.com
VITE_AUTHX_CLIENT_ID=spa-client-id
VITE_AUTHX_REDIRECT_URI=http://localhost:5174
```
