# authx-rs

[![Crates.io](https://img.shields.io/crates/v/authx-core.svg)](https://crates.io/crates/authx-core)
[![docs.rs](https://docs.rs/authx-core/badge.svg)](https://authx-rs.hamat-ibrahim3.workers.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/hamzzy/authx-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hamzzy/authx-rs/actions)

An authentication and authorization framework for Rust.

**Philosophy:** Zero-cost abstractions, trait-based, `async`-native. Every feature is a plugin, nothing is hardcoded.

---

## Architecture

```
                    ┌───────────┐  ┌─────────────┐
                    │ authx-cli │  │  dashboard  │
                    └─────┬─────┘  └──────┬──────┘
                          │               │
          ┌───────────────▼───────────────▼──────────────┐
          │           authx-axum  (HTTP layer)           │
          │  SessionLayer  RateLimitLayer  CSRF  Routes  │
          └──────────────────────┬───────────────────────┘
                                 │
   ┌─────────────────────────────▼─────────────────────────────┐
   │                   authx-plugins  (features)               │
   │                                                           │
   │  EmailPassword   TOTP         MagicLink    PasswordReset  │
   │  OAuth           OIDC Provider/Federation  WebAuthn       │
   │  ApiKey          EmailOTP     Admin        Organization   │
   └─────────────────────────────┬─────────────────────────────┘
                                 │
   ┌─────────────────────────────▼─────────────────────────────┐
   │               authx-core  (zero-dep engine)               │
   │                                                           │
   │  Crypto (Argon2id · AES-256-GCM)    JWT / EdDSA signing   │
   │  RBAC + ABAC policy engine          EventBus              │
   │  Brute-force lockout                Key rotation          │
   └─────────────────────────────┬─────────────────────────────┘
                                 │
   ┌─────────────────────────────▼─────────────────────────────┐
   │              authx-storage  (repository ports)            │
   │                                                           │
   │  MemoryStore (dev/test)             PostgresStore (sqlx)  │
   │  AuditLogger                        RedisTokenStore       │
   │  Bring your own adapter                                   │
   └───────────────────────────────────────────────────────────┘
```

### Design constraints

| Constraint | Detail |
|---|---|
| Framework-agnostic core | `authx-core` has zero axum/actix imports |
| Storage-agnostic | Pluggable `Repository` traits; bring your own adapter |
| Password hashing | Argon2id only (65536 mem / 3 iter / 4 parallelism) |
| Session tokens | SHA-256 hashed before storage, raw token sent to client once |
| JWT signing | Ed25519 / EdDSA via `jsonwebtoken` |
| CSRF | Origin/Referer trusted-origin check for mutating requests |

---

## Workspace layout

```
crates/
  authx-core/       # Models, crypto, events, RBAC/ABAC policy, identity
  authx-storage/    # Repository traits + MemoryStore + PostgresStore
  authx-plugins/    # Plugin trait + all auth plugins
  authx-axum/       # Tower middleware, route handlers, cookies, CSRF, rate limiting
  authx-cli/        # CLI binary (serve, migrate, user, key, oidc)
  authx-dashboard/  # Admin dashboard (HTMX)
examples/
  fullstack-app/    # End-to-end: React + Axum + PostgreSQL + SDK + TOTP MFA
  axum-app/         # Full working Axum integration demo
  actix-app/        # Direct actix-web integration demo
  react-sdk-app/    # React consumer app for the TypeScript SDK packages
  vue-sdk-app/      # Vue consumer app for the TypeScript SDK packages
packages/
  authx-sdk-ts/     # Low-level TypeScript SDK: OIDC, JWKS, PKCE, device, session helpers
  authx-sdk-web/    # Browser token storage, authenticated fetch, and refresh orchestration
  authx-sdk-react/  # React provider/hooks for authx token clients
  authx-sdk-vue/    # Vue plugin/composable for authx token clients
```

---

## Quickstart

```toml
# Cargo.toml
[dependencies]
authx-core    = "0.1"
authx-storage = "0.1"
authx-plugins = "0.1"
authx-axum    = "0.1"
```

```rust
use authx_storage::memory::MemoryStore;
use authx_plugins::EmailPasswordService;
use authx_axum::{AuthxState, SessionLayer, RequireAuth};
use authx_core::events::EventBus;
use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    let store  = MemoryStore::new();
    let events = EventBus::new();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET required");

    let state = AuthxState::new(
        store.clone(),
        events.clone(),
        jwt_secret,
        3600, // session TTL seconds
    );

    let app = Router::new()
        .route("/me", get(me_handler).layer(RequireAuth::new()))
        .nest("/auth", authx_axum::handlers::auth_router(state.clone()))
        .layer(SessionLayer::new(store, jwt_secret));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

See [examples/axum-app/src/main.rs](examples/axum-app/src/main.rs) for a complete example.

---

## Features

### Email + Password authentication

```rust
use authx_plugins::EmailPasswordService;
use authx_core::brute_force::LockoutConfig;

// Basic setup
let svc = EmailPasswordService::new(store.clone(), events.clone(), 3600);

// With brute-force lockout (5 failures → 15-min lockout)
let svc = EmailPasswordService::new(store.clone(), events.clone(), 3600)
    .with_lockout(LockoutConfig { max_failures: 5, window_secs: 900 });

let resp = svc.sign_up("user@example.com", "securepassword").await?;
let resp = svc.sign_in("user@example.com", "securepassword", "127.0.0.1").await?;
// resp.token  — JWT, send to client
// resp.session — full Session model
```

### TOTP MFA

```rust
use authx_plugins::TotpService;

let svc = TotpService::new(store.clone(), "MyApp");

// Enrollment
let setup = svc.begin_setup(user_id).await?;
// setup.otpauth_uri → generate QR code, show to user
// setup.backup_codes → show once, store securely

// Confirm user can produce a valid code, then persist
svc.confirm_setup(user_id, &setup, "123456").await?;

// Verify on sign-in
svc.verify(TotpVerifyRequest { user_id, code: "123456".into() }).await?;
```

### Magic link authentication

```rust
use authx_plugins::MagicLinkService;

let svc = MagicLinkService::new(store.clone(), events.clone(), 3600);

// Issue token (send in email yourself — authx does not send email)
let token = svc.request_link("user@example.com").await?; // None if unknown

// User clicks link → verify and create session
let resp = svc.verify(&token.unwrap(), "client-ip").await?;
// resp.token → JWT session token
```

### Password reset

```rust
use authx_plugins::PasswordResetService;

let svc = PasswordResetService::new(store.clone(), events.clone());

// 30-minute token (send in email yourself)
let token = svc.request_reset("user@example.com").await?; // None if unknown

// User submits new password
svc.reset_password(PasswordResetRequest {
    token:        token.unwrap(),
    new_password: "newSecurePassword123".into(),
}).await?;
```

### Admin operations

```rust
use authx_plugins::AdminService;

let svc = AdminService::new(store.clone(), events.clone(), 3600);

svc.ban_user(admin_id, user_id, "violated ToS").await?;
svc.unban_user(admin_id, user_id).await?;

// Impersonate — creates a tagged session for support/debugging
let (session, token) = svc.impersonate(admin_id, target_id, "admin-ip").await?;
```

### RBAC + ABAC authorization

```rust
use authx_core::policy::{AuthzEngine, AuthzRequest};
use authx_core::policy::builtin::{
    OrgBoundaryPolicy, RequireEmailVerifiedPolicy,
    IpAllowListPolicy, TimeWindowPolicy,
};

let mut engine = AuthzEngine::new();
engine.add_policy(OrgBoundaryPolicy);
engine.add_policy(RequireEmailVerifiedPolicy::for_prefix("admin."));
engine.add_policy(IpAllowListPolicy::new(["10.0.0.0/8"]));
// engine.add_policy(TimeWindowPolicy::weekdays(9, 18)); // 09–18 UTC, Mon–Fri

// Enforce — returns Err(AuthError::Forbidden) on denial
engine.enforce("admin.delete_user", &identity, Some("org:acme-uuid:reports")).await?;
```

### Key rotation (zero-downtime)

```rust
use authx_core::KeyRotationStore;

let store = KeyRotationStore::new(3); // keep at most 3 key versions
store.add_key("v1", PRIV_PEM_V1, PUB_PEM_V1)?;

// Later — rotate without dropping existing token validity
store.rotate("v2", PRIV_PEM_V2, PUB_PEM_V2)?;

let token  = store.sign(user_id, 3600, serde_json::Value::Null)?;
let claims = store.verify(&token)?; // tries v2 first, falls back to v1
```

### Rate limiting

```rust
use authx_axum::rate_limit::RateLimitLayer;
use std::time::Duration;

// 20 requests per minute per IP on auth routes
let rate_limit = RateLimitLayer::new(20, Duration::from_secs(60));
let auth_routes = Router::new()
    .nest("/auth", auth_router)
    .layer(rate_limit);
```

### Audit logging

```rust
use authx_storage::AuditLogger;

// Subscribes to EventBus and writes every auth event to storage asynchronously.
AuditLogger::new(store.clone(), events.clone()).run();

// Query logs
let logs = store.find_audit_logs_by_user(user_id, 50).await?;
```

---

## Storage adapters

### In-memory (tests / development)

```rust
use authx_storage::memory::MemoryStore;
let store = MemoryStore::new();
```

### PostgreSQL (production)

```toml
authx-storage = { version = "0.1", features = ["sqlx-postgres"] }
```

```rust
use authx_storage::PostgresStore;

let store = PostgresStore::connect("postgres://user:pass@host/db").await?;
store.migrate().await?; // runs bundled migrations automatically
```

---

## Security defaults

| Concern | Default |
|---|---|
| Password hashing | Argon2id · m=65536 · t=3 · p=4 |
| JWT algorithm | EdDSA (Ed25519) |
| Session token storage | SHA-256 hex hash only — plaintext discarded immediately |
| OAuth token storage | AES-256-GCM encrypted |
| CSRF protection | Origin/Referer trusted-origin check on all mutating methods |
| Brute-force lockout | Sliding window — configurable threshold + window |
| Rate limiting | Per-IP sliding window — configurable threshold + window |
| Magic link TTL | 15 minutes, single-use |
| Password reset TTL | 30 minutes, single-use |
| Cookie flags | HttpOnly · SameSite=Lax · Secure (configurable) · Path=/ |

---

## Running tests

```bash
cargo test --workspace
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork and clone** the repository.
2. **Create a branch** from `main` for your change.
3. **Run the test suite** before submitting:
   ```bash
   cargo test --workspace
   cargo clippy --workspace -- -D warnings
   cargo fmt --all -- --check
   ```
4. **Open a pull request** against `main`. CI runs the same checks above — all must pass.

### Guidelines

- Keep PRs focused — one feature or fix per PR.
- Add tests for new functionality. Existing plugins are good reference (`crates/authx-plugins/src/*/tests.rs`).
- Public API changes should update the relevant docs and README examples.
- Follow existing code style — `rustfmt` defaults, no unsafe unless strictly necessary.
- Security-sensitive changes (crypto, session handling, token storage) require extra review. Please call this out in the PR description.

### Reporting issues

Open an issue on [GitHub](https://github.com/hamzzy/authx-rs/issues). For security vulnerabilities, please email the maintainers directly instead of filing a public issue.

---