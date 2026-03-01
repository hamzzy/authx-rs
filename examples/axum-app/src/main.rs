/// axum-app — minimal Axum integration example for authx-rs
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
///   # Sign out (all devices)
///   curl -s -b /tmp/jar -X POST http://localhost:3000/auth/sign-out/all \
///        -H 'Origin: http://localhost:3000'
///
///   # Protected app route
///   curl -s -b /tmp/jar http://localhost:3000/me
use std::time::Duration;

use axum::{middleware, response::Json, routing::get, Router};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use authx_axum::{
    csrf_middleware, AuthxState, CsrfConfig, RateLimitConfig, RateLimitLayer, RequireAuth,
    SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_storage::MemoryStore;

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

    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .nest("/auth", auth_router)
        // SessionLayer resolves Identity on every request
        .layer(SessionLayer::new(store))
        .layer(TraceLayer::new_for_http());

    let addr = "0.0.0.0:3000";
    tracing::info!("listening on http://{addr}");

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
