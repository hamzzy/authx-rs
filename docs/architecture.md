# authx-rs Architecture

This document is a contributor-oriented architecture overview for the workspace. The public docs site has user-facing material under `docs/src/content/docs`, while this file is meant to explain the crate boundaries and the intended layering inside the repository.

## Workspace layout

```text
crates/
  authx-core/        Domain models, crypto, events, policy engine, key rotation
  authx-storage/     Repository traits, memory store, PostgreSQL implementation
  authx-plugins/     Authentication and identity services built on core + storage
  authx-axum/        Axum/Tower HTTP integration, middleware, routers, extractors
  authx-dashboard/   Embedded admin dashboard UI and API
  authx-cli/         CLI for serving, migrations, and operational tasks
examples/
  axum-app/          End-to-end integration demo
```

## Layering

```text
┌──────────────────────────────────────────────────────────────┐
│ Transport / Ops                                             │
│ authx-axum · authx-dashboard · authx-cli · examples         │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Application services                                         │
│ authx-plugins: sign-in flows, MFA, OIDC provider/federation, │
│ organizations, admin, one-time token orchestration           │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Domain core                                                  │
│ authx-core: models, auth errors, crypto, EventBus, RBAC /    │
│ ABAC policy engine, identity model, lockout and key rotation │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Persistence ports and adapters                               │
│ authx-storage: repository traits, MemoryStore, PostgresStore │
└──────────────────────────────────────────────────────────────┘
```

## Dependency rules

- `authx-core` must stay free of HTTP framework and database-driver concerns.
- `authx-storage` depends on `authx-core` and implements repository ports.
- `authx-plugins` may depend on `authx-core` and `authx-storage`, but should not own transport concerns.
- `authx-axum`, `authx-dashboard`, and `authx-cli` are thin integration layers around plugins and storage.
- Example crates should demonstrate composition, not introduce new core behavior.

## Key components

### `authx-core`

- Domain models for users, sessions, organizations, OIDC, API keys, invites, and audit logs.
- Cryptographic helpers for password hashing, token hashing, AES-GCM encryption, and Ed25519 key rotation.
- `EventBus` and `AuthEvent` types for audit and observability hooks.
- Authorization engine and built-in RBAC / ABAC policies.

### `authx-storage`

- Repository traits such as `UserRepository`, `SessionRepository`, `OrgRepository`, and OIDC repositories.
- `StorageAdapter` blanket trait used by higher layers to avoid large explicit trait lists at call sites.
- In-memory adapter for tests/examples and SQLx-backed PostgreSQL adapter for production-style deployments.

### `authx-plugins`

- Auth flows: email/password, username, magic link, email OTP, OAuth, anonymous, API keys, password reset, email verification.
- MFA and possession factors: TOTP, WebAuthn.
- Organizational and admin operations.
- OIDC provider and federation services.

### `authx-axum`

- Session resolution middleware and auth extractors.
- Built-in handlers/routers for auth endpoints, OIDC provider, federation, and WebAuthn.
- CSRF and rate-limiting helpers.

### `authx-dashboard`

- Embedded admin surface for managing users, sessions, OIDC clients, device codes, and federation providers.

### `authx-cli`

- Operational binary for serving the app, running migrations, seeding, and creating OIDC config records.

## Cross-cutting flows

### Session-based browser auth

1. A plugin authenticates the user.
2. A 32-byte opaque session token is generated.
3. Only the SHA-256 hash is stored in the session repository.
4. `authx-axum` sets the raw token in an `HttpOnly` cookie.
5. `SessionLayer` resolves the cookie back into an `Identity` on subsequent requests.

### OIDC provider

1. Client metadata is stored via `OidcClientRepository`.
2. `/authorize` validates client and redirect URI, then creates a short-lived auth code.
3. `/token` exchanges the code for JWT access tokens and opaque refresh tokens.
4. `/userinfo`, `/jwks`, `/introspect`, `/revoke`, and device-code routes sit on top of the same service.

### OIDC federation

1. A stored federation provider record contains issuer, client ID, encrypted client secret, scopes, and optional claim-mapping rules.
2. Federation begin discovers the upstream IdP and builds a PKCE-protected authorization redirect.
3. Callback exchanges the code, fetches userinfo, upserts the local user/account mapping, applies claim mappings, and creates a local authx session.

## Extension points

- New storage backends should implement repository traits in `authx-storage`.
- New auth mechanisms belong in `authx-plugins`, with transport glue added separately.
- New framework integrations should follow the `authx-axum` pattern: thin adapters over shared services.
