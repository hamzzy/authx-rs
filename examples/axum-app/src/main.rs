/// axum-app — full Axum integration example for authx-rs
///
/// Demonstrates:
///  - MemoryStore (zero config, no DB required to run)
///  - SessionLayer (resolves Identity on every request)
///  - CSRF trusted-origin check on mutating endpoints
///  - Cookie-based session management (httpOnly, SameSite=Lax)
///  - Protected routes via RequireAuth extractor
///  - Per-device session listing and revocation
///  - Per-IP rate limiting on auth endpoints
///  - Brute-force / account lockout after repeated failures
///  - OIDC Provider (authx as IdP) — /oidc/.well-known/openid-configuration
///  - OIDC Federation (inbound SSO) — /auth/federation/:provider/begin
///
/// Run:
///   cargo run -p axum-app
///
/// Test with curl:
///   # Register
///   curl -s -X POST http://localhost:3000/auth/sign-up \
///        -H 'Content-Type: application/json' \
///        -H 'Origin: http://localhost:3000' \
///        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'
///
///   # Sign in — saves authx_session cookie to /tmp/jar
///   curl -s -c /tmp/jar -X POST http://localhost:3000/auth/sign-in \
///        -H 'Content-Type: application/json' \
///        -H 'Origin: http://localhost:3000' \
///        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'
///
///   # Protected: current session info
///   curl -s -b /tmp/jar http://localhost:3000/auth/session
///
///   # Protected: list all active sessions
///   curl -s -b /tmp/jar http://localhost:3000/auth/sessions
///
///   # OIDC discovery
///   curl -s http://localhost:3000/oidc/.well-known/openid-configuration
///
///   # Protected app route
///   curl -s -b /tmp/jar http://localhost:3000/me
use std::sync::Arc;
use std::time::Duration;

use axum::{middleware, response::Json, routing::get, Router};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use authx_axum::{
    csrf_middleware, oidc_federation_router, oidc_provider_router, AuthxState, CsrfConfig,
    OidcProviderState, RateLimitConfig, RateLimitLayer, RequireAuth, SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_core::KeyRotationStore;
use authx_plugins::oidc_provider::OidcProviderConfig;
use authx_plugins::{oidc_federation::OidcFederationService, oidc_provider::OidcProviderService};
use authx_storage::MemoryStore;

// Ed25519 test keys — NEVER use in production; generate your own.
const PRIV_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYDHbiFQiDpMqQR5JN9QOCiIxj7T/XmVbz3Cg+xvL\n-----END PRIVATE KEY-----\n";
const PUB_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoNFBPj4h5jFITR2XlDqz8qFjNXaXFJF3mJoSBpVwC1E=\n-----END PUBLIC KEY-----\n";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,authx=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = MemoryStore::new();
    let secure = false; // set true in production (HTTPS required)

    // 5 failures within 15 minutes triggers lockout.
    let lockout_cfg = LockoutConfig::new(5, Duration::from_secs(60 * 15));

    let authx_state = AuthxState::new_with_lockout(
        store.clone(),
        60 * 60 * 24 * 30, // 30-day sessions
        secure,
        lockout_cfg,
    );

    let csrf_config = CsrfConfig::new(["http://localhost:3000", "https://yourdomain.com"]);

    // 20 requests per minute per IP on auth routes.
    let auth_rate_limit = RateLimitLayer::new(RateLimitConfig::new(20, Duration::from_secs(60)));

    let auth_router = authx_state
        .router()
        .layer(auth_rate_limit)
        .route_layer(middleware::from_fn_with_state(csrf_config, csrf_middleware));

    // ── OIDC Provider (authx as IdP) ────────────────────────────────────────
    let key_store = KeyRotationStore::new(3);
    key_store
        .add_key("v1", PRIV_PEM, PUB_PEM)
        .expect("test key pair should load");

    let oidc_config = OidcProviderConfig {
        issuer: "http://localhost:3000".into(),
        key_store: key_store.clone(),
        access_token_ttl_secs: 3600,
        id_token_ttl_secs: 3600,
        refresh_token_ttl_secs: 60 * 60 * 24 * 30,
        auth_code_ttl_secs: 600,
        device_code_ttl_secs: 600,
        device_code_interval_secs: 5,
        verification_uri: "http://localhost:3000/oidc/device".into(),
    };

    let oidc_service = OidcProviderService::new(store.clone(), oidc_config.clone());

    let oidc_state = OidcProviderState {
        service: Arc::new(oidc_service),
        config: oidc_config,
        issuer: "http://localhost:3000".into(),
        base_path: "/oidc".into(),
        public_pem: PUB_PEM.to_vec(),
        jwks_kid: "v1".into(),
    };

    let oidc_router = oidc_provider_router(oidc_state);

    // ── OIDC Federation (inbound SSO from external IdPs) ────────────────────
    // To use: create a federation provider record (via dashboard or direct DB),
    // then redirect users to /auth/federation/{provider}/begin?redirect_uri=...
    let encryption_key: [u8; 32] = rand::random();
    let federation_svc = OidcFederationService::new(
        store.clone(),
        60 * 60 * 24 * 30, // session TTL
        encryption_key,
    );
    let federation_router = oidc_federation_router(Arc::new(federation_svc));

    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .nest("/auth", auth_router)
        .nest("/auth/federation", federation_router)
        .nest("/oidc", oidc_router)
        // SessionLayer resolves Identity on every request
        .layer(SessionLayer::new(store))
        .layer(TraceLayer::new_for_http());

    let addr = "0.0.0.0:3000";
    tracing::info!("listening on http://{addr}");
    tracing::info!("OIDC discovery: http://{addr}/oidc/.well-known/openid-configuration");
    tracing::info!("Federation SSO: http://{addr}/auth/federation/{{provider}}/begin");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn me(RequireAuth(identity): RequireAuth) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id":    identity.user.id,
        "email":      identity.user.email,
        "verified":   identity.user.email_verified,
        "active_org": identity.active_org,
    }))
}
