# fullstack-app

End-to-end example: **React frontend** + **Axum backend** + **PostgreSQL** + **authx SDKs**.

Demonstrates:
- Email/password sign-up and sign-in
- Plugin service coverage for API keys, admin actions, and organizations/invites
- OIDC authorization code flow with PKCE (React SDK)
- OIDC token refresh, introspection, revocation, and userinfo debugging
- Device Authorization Grant (device code flow)
- TOTP MFA enrollment and verification
- WebAuthn / passkey registration and login
- Cookie-based session management
- Session listing and revocation
- Runtime config and raw endpoint inspection for debugging
- CSRF protection and rate limiting

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (for PostgreSQL)
- [Node.js](https://nodejs.org/) >= 18 (for the React frontend)
- [Rust](https://rustup.rs/) (for the Axum backend)

## Quick start

```bash
# 1. Start PostgreSQL
docker compose -f examples/fullstack-app/docker-compose.yml up -d

# 2. Start the backend (from repo root)
DATABASE_URL=postgres://authx:authx@localhost:5433/authx cargo run -p fullstack-app

DATABASE_URL=postgres://app:app@/authx cargo run -p fullstack-app

# 3. Start the React frontend (in another terminal)
cd examples/fullstack-app/client
npm install
npm run dev

# 4. Open http://localhost:5173
```

## Architecture

```
Browser (:5173)                    Backend (:4000)              Postgres (:5433)
┌──────────────┐  Vite proxy      ┌──────────────┐             ┌─────────┐
│  React app   │ ───────────────> │  Axum server │ ──────────> │  PG 16  │
│  sdk-react   │  /auth, /oidc    │  authx-axum  │  sqlx       │  authx  │
│  sdk-web     │  /me             │  PostgreStore│             │         │
└──────────────┘                  └──────────────┘             └─────────┘
```

The Vite dev server proxies `/auth`, `/oidc`, `/plugins`, `/debug`, `/me`, and `/health` to the backend so the browser talks to a single origin — no CORS issues during development.

Because this example uses authx as both the application backend and the OIDC provider, the `/oidc/authorize` endpoint expects an existing authx session cookie. Sign in with email/password first, then start the OIDC PKCE flow from the dashboard.

The frontend also reads `/debug/config` at runtime, so backend restarts no longer require manually copying a fresh `client_id` into the client unless you want to override it.

## What to try

1. **Sign up** — create an account with email and password.
2. **Sign in** — start a cookie-based session.
3. **Enable TOTP** — enroll your authenticator app, confirm with a code.
4. **Verify TOTP** — prove your code works.
5. **OIDC login** — after signing in locally, start the PKCE authorization code flow using `@authx-rs/sdk-react`.
6. **OIDC debug tools** — inspect discovery, userinfo, introspection, revocation, refresh, and the current SDK token snapshot.
7. **Device code flow** — request a device code, authorize it through the verification page, then poll the token endpoint.
8. **Passkeys** — register a passkey for the current user, then test passkey login from the signed-in or signed-out view.
9. **Plugin: API keys** — create, list, revoke, and authenticate raw API keys.
10. **Plugin: admin** — list users, provision users, ban/unban, revoke sessions, and impersonate.
11. **Plugin: organizations** — create orgs, create roles, issue raw invite tokens, accept invites, and switch the active org on the current session.
12. **Sessions** — list all active sessions, inspect `/auth/session`, and revoke any of them.
13. **Sign out** — destroy the current session or all sessions.

## Teardown

```bash
docker compose -f examples/fullstack-app/docker-compose.yml down -v
```
