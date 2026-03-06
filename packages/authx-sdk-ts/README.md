# @authx/sdk

TypeScript SDK for `authx-rs`.

Current scope:

- OIDC discovery
- JWKS fetch and key selection helpers
- PKCE helpers
- authorization URL builder
- code exchange / refresh / revoke / introspection / userinfo helpers
- device authorization helpers
- cookie-session convenience helpers for authx browser endpoints
- typed SDK errors

Non-goals in this package:

- no CommonJS build; the package is ESM-only
- higher-level token storage and auto-refresh orchestration live in `@authx/sdk-web`
- React integration helpers live in `@authx/sdk-react`
- Vue integration helpers live in `@authx/sdk-vue`

The package is intentionally dependency-free and expects modern runtimes with `fetch` and Web Crypto support.

Runtime target:

- modern browsers
- Node 18+ for `fetch`, `URL`, and Web Crypto support
- npm 9+ for local development and publishing

## Development

```bash
npm install
npm test
npm pack --dry-run
```

The published package includes:

- ESM build in `dist/esm`
- declaration files in `dist/types`

## Publish

```bash
cd packages/authx-sdk-ts
npm install
npm test
npm pack --dry-run
npm publish --access public
```
