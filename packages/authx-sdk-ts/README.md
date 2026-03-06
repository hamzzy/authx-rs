# @authx/sdk

Initial TypeScript SDK scaffold for `authx-rs`.

Current scope:

- OIDC discovery
- PKCE helpers
- authorization URL builder
- code exchange / refresh / revoke / introspection / userinfo helpers
- device authorization helpers
- cookie-session convenience helpers for authx browser endpoints
- typed SDK errors

The package is intentionally dependency-free and expects modern runtimes with `fetch` and Web Crypto support.
