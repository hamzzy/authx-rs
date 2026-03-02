# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-03-02

### Added

#### authx-core
- `User`, `Session`, `Organization`, `Membership`, `Role` domain models with full serde support
- Argon2id password hashing (m=65536, t=3, p=4) via `PasswordHasher`
- AES-256-GCM token encryption for OAuth credential storage
- Ed25519 / EdDSA JWT signing and verification via `jsonwebtoken`
- `KeyRotationStore` — versioned Ed25519 keys, `kid` JWT header, zero-downtime rotation (keeps N previous versions)
- `EventBus` — async publish/subscribe for auth events (`UserCreated`, `UserSignedIn`, `UserSignedOut`, etc.)
- `AuthzEngine` — trait-based RBAC + ABAC authorization with short-circuit deny/allow
- Built-in ABAC policies: `OrgBoundaryPolicy`, `TimeWindowPolicy`, `IpAllowListPolicy`, `RequireEmailVerifiedPolicy`
- `Identity` struct — resolved user + session + active org + active membership for request context
- `LoginAttemptTracker` + `LockoutConfig` — sliding-window brute-force lockout

#### authx-storage
- `UserRepository`, `SessionRepository`, `CredentialRepository`, `OrganizationRepository`, `AuditLogRepository` traits
- `StorageAdapter` blanket impl — any `T` satisfying all repo traits automatically satisfies `StorageAdapter`
- `MemoryStore` — thread-safe in-memory implementation (ideal for tests and local development)
- `PostgresStore` — `sqlx` 0.8 adapter with bundled migrations for all tables
- `AuditLogger<S>` — subscribes to `EventBus` and writes every auth event to storage asynchronously
- SQL migrations: `authx_users`, `authx_sessions`, `authx_credentials`, `authx_orgs`, `authx_roles`, `authx_memberships`, `authx_audit_logs`

#### authx-plugins
- `EmailPasswordService` — sign-up, sign-in, sign-out, sign-out-all, list-sessions; Argon2id hashing
- `TotpService` — TOTP enrolment, confirmation, verification, disable, backup codes (8 × 8-char codes)
- `MagicLinkService` — 15-minute single-use tokens; creates full session on verify
- `PasswordResetService` — 30-minute single-use tokens; no email enumeration; enforces new ≠ old
- `AdminService` — ban/unban, ban status check, impersonation, list/revoke sessions
- `ApiKeyService` — create, list, revoke, authenticate; SHA-256 hash stored, raw key returned once
- `EmailVerificationService` — send/verify email confirmation tokens
- `OAuthService` — OAuth2 authorization code flow with PKCE; token storage AES-256-GCM encrypted
- Organization management — create org, add/remove members, assign roles

#### authx-axum
- `SessionLayer` / `SessionService` — Tower `Layer`/`Service` pattern; attaches `Identity` to request extensions
- `RequireAuth` — Tower layer that rejects unauthenticated requests with `401`
- `RateLimitLayer` / `RateLimitService` — per-IP sliding-window rate limiting
- CSRF protection — Origin/Referer trusted-origin check on all mutating HTTP methods
- Cookie management — `HttpOnly`, `SameSite=Lax`, `Secure`, `Path=/` defaults
- `AuthErrorResponse` newtype for `IntoResponse` orphan rule compliance
- Built-in route handlers: sign-up, sign-in, sign-out, sign-out-all, me, refresh, verify-email

#### authx-dashboard
- Embedded HTMX-powered admin UI served at `/dashboard`
- Bearer token authentication for all API routes
- REST endpoints: list/create/get users, ban/unban, list/revoke sessions

#### authx-cli
- `authx serve` — start the auth server (MemoryStore or PostgreSQL via `DATABASE_URL`)
- `authx migrate` — run database migrations
- `authx user list / create` — manage users from the terminal
- `authx key generate / list / revoke` — manage API keys from the terminal

### Security
- Session tokens: SHA-256 hashed before storage; raw token sent to client exactly once
- OAuth tokens: AES-256-GCM encrypted at rest
- Passwords: Argon2id with OWASP-recommended parameters
- JWTs: EdDSA (Ed25519) only; HMAC-SHA algorithms explicitly not supported
- Magic link and password reset tokens: single-use with short TTL enforced in storage layer

[0.1.0]: https://github.com/hamzzy/authx-rs/releases/tag/v0.1.0
