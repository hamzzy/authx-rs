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

use axum::{
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Json, Redirect},
    routing::get,
    Router,
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use authx_axum::{
    csrf_middleware, oidc_federation_router, oidc_provider_router, AuthxState, CsrfConfig,
    OidcProviderState, RateLimitConfig, RateLimitLayer, RequireAuth, SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_core::crypto::{encrypt, sha256_hex};
use authx_core::models::{CreateOidcClient, CreateOidcFederationProvider};
use authx_core::KeyRotationStore;
use authx_plugins::oidc_provider::OidcProviderConfig;
use authx_plugins::{oidc_federation::OidcFederationService, oidc_provider::OidcProviderService};
use authx_storage::ports::{OidcClientRepository, OidcFederationProviderRepository};
use authx_storage::MemoryStore;

// Ed25519 test keys — NEVER use in production; generate your own.
const PRIV_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYDHbiFQiDpMqQR5JN9QOCiIxj7T/XmVbz3Cg+xvL\n-----END PRIVATE KEY-----\n";
const PUB_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoNFBPj4h5jFITR2XlDqz8qFjNXaXFJF3mJoSBpVwC1E=\n-----END PUBLIC KEY-----\n";
const BASE_URL: &str = "http://localhost:3000";
const DEMO_OIDC_CALLBACK: &str = "http://localhost:3000/demo/oidc/callback";
const DEMO_FEDERATION_PROVIDER: &str = "self";
const DEMO_FEDERATION_CALLBACK: &str = "http://localhost:3000/auth/federation/self/callback";
const DEMO_FEDERATION_SECRET: &str = "demo-federation-secret";

#[derive(Clone)]
struct DemoState {
    oidc_service: Arc<OidcProviderService<MemoryStore>>,
    oidc_client_id: String,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: String,
    #[allow(dead_code)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SsoQuery {
    provider: Option<String>,
}

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
        issuer: BASE_URL.into(),
        key_store: key_store.clone(),
        access_token_ttl_secs: 3600,
        id_token_ttl_secs: 3600,
        refresh_token_ttl_secs: 60 * 60 * 24 * 30,
        auth_code_ttl_secs: 600,
        device_code_ttl_secs: 600,
        device_code_interval_secs: 5,
        verification_uri: format!("{BASE_URL}/oidc/device"),
    };

    let oidc_service = Arc::new(OidcProviderService::new(store.clone(), oidc_config.clone()));

    let demo_oidc_client = OidcClientRepository::create(
        &store,
        CreateOidcClient {
            name: "axum-app public demo client".into(),
            redirect_uris: vec![DEMO_OIDC_CALLBACK.into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            allowed_scopes: "openid profile email".into(),
            secret_hash: String::new(),
        },
    )
    .await
    .expect("demo OIDC client should seed");

    let oidc_state = OidcProviderState {
        service: oidc_service.clone(),
        config: oidc_config,
        issuer: BASE_URL.into(),
        base_path: "/oidc".into(),
        public_pem: PUB_PEM.to_vec(),
        jwks_kid: "v1".into(),
    };

    let oidc_router = oidc_provider_router(oidc_state);

    // ── OIDC Federation (inbound SSO from external IdPs) ────────────────────
    // To use: create a federation provider record (via dashboard or direct DB),
    // then redirect users to /auth/federation/{provider}/begin?redirect_uri=...
    let encryption_key: [u8; 32] = rand::random();
    let demo_federation_client = OidcClientRepository::create(
        &store,
        CreateOidcClient {
            name: "axum-app federation demo client".into(),
            redirect_uris: vec![DEMO_FEDERATION_CALLBACK.into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            allowed_scopes: "openid profile email".into(),
            secret_hash: sha256_hex(DEMO_FEDERATION_SECRET.as_bytes()),
        },
    )
    .await
    .expect("demo federation client should seed");
    let secret_enc = encrypt(&encryption_key, DEMO_FEDERATION_SECRET.as_bytes())
        .expect("demo federation secret should encrypt");
    OidcFederationProviderRepository::create(
        &store,
        CreateOidcFederationProvider {
            name: DEMO_FEDERATION_PROVIDER.into(),
            issuer: format!("{BASE_URL}/oidc"),
            client_id: demo_federation_client.client_id.clone(),
            secret_enc,
            scopes: "openid profile email".into(),
            org_id: None,
            claim_mapping: vec![],
        },
    )
    .await
    .expect("demo federation provider should seed");
    let federation_svc = OidcFederationService::new(
        store.clone(),
        60 * 60 * 24 * 30, // session TTL
        encryption_key,
    );
    let federation_router = oidc_federation_router(Arc::new(federation_svc));
    let demo_state = DemoState {
        oidc_service,
        oidc_client_id: demo_oidc_client.client_id.clone(),
    };
    let demo_router = Router::new()
        .route("/", get(index))
        .route("/demo/oidc/login", get(demo_oidc_login))
        .route("/demo/oidc/callback", get(demo_oidc_callback))
        .route("/demo/sso", get(demo_sso_login))
        .with_state(demo_state);

    let app = demo_router
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
    tracing::info!(
        "Demo OIDC login: {BASE_URL}/demo/oidc/login (client_id = {})",
        demo_oidc_client.client_id
    );
    tracing::info!("Demo federation provider: {DEMO_FEDERATION_PROVIDER}");
    tracing::info!("Federation SSO: {BASE_URL}/demo/sso?provider={DEMO_FEDERATION_PROVIDER}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<DemoState>) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>authx-rs axum-app</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem auto; max-width: 56rem; line-height: 1.5; padding: 0 1rem; }}
    code, pre {{ background: #f6f8fa; border-radius: 6px; }}
    code {{ padding: 0.15rem 0.35rem; }}
    pre {{ padding: 1rem; overflow-x: auto; }}
    a, button {{ color: #0f5fff; }}
    .card {{ border: 1px solid #d0d7de; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }}
    .muted {{ color: #57606a; }}
    input {{ font: inherit; padding: 0.45rem 0.6rem; min-width: 18rem; }}
    button {{ font: inherit; padding: 0.45rem 0.7rem; }}
  </style>
</head>
<body>
  <h1>authx-rs axum-app</h1>
  <p class="muted">This example now seeds a public OIDC demo client and a federation provider named <code>{}</code>.</p>

  <div class="card">
    <h2>1. Create a local session first</h2>
    <p>Use the existing JSON auth endpoints from another terminal:</p>
    <pre>curl -s -X POST {}/auth/sign-up \
  -H 'Content-Type: application/json' \
  -H 'Origin: {}' \
  -d '{{"email":"alice@example.com","password":"hunter2hunter2"}}'

curl -s -c /tmp/jar -X POST {}/auth/sign-in \
  -H 'Content-Type: application/json' \
  -H 'Origin: {}' \
  -d '{{"email":"alice@example.com","password":"hunter2hunter2"}}'</pre>
    <p class="muted">The OIDC provider <code>/authorize</code> route requires an authenticated authx session.</p>
  </div>

  <div class="card">
    <h2>2. Demo authx as an OIDC provider</h2>
    <p>Seeded public client ID: <code>{}</code></p>
    <p><a href="/demo/oidc/login">Start authorization-code flow against authx itself</a></p>
    <p class="muted">The callback exchanges the code and renders token + userinfo output.</p>
  </div>

  <div class="card">
    <h2>3. Demo OIDC federation</h2>
    <form action="/demo/sso" method="get">
      <input name="provider" value="{}" />
      <button type="submit">Start SSO flow</button>
    </form>
    <p class="muted">The seeded provider points federation back at this app's own OIDC provider. The callback endpoint returns JSON and sets <code>authx_session</code>; after that, visit <a href="/me">/me</a>.</p>
  </div>

  <div class="card">
    <h2>Useful endpoints</h2>
    <p><a href="/health">/health</a></p>
    <p><a href="/oidc/.well-known/openid-configuration">OIDC discovery</a></p>
    <p><a href="/me">/me</a></p>
  </div>
</body>
</html>"#,
        DEMO_FEDERATION_PROVIDER,
        BASE_URL,
        BASE_URL,
        BASE_URL,
        BASE_URL,
        state.oidc_client_id,
        DEMO_FEDERATION_PROVIDER,
    ))
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

async fn demo_oidc_login(State(state): State<DemoState>) -> Redirect {
    let authorize_url = format!(
        "{BASE_URL}/oidc/authorize?client_id={}&redirect_uri={DEMO_OIDC_CALLBACK}&response_type=code&scope=openid%20profile%20email&state=demo-self-oidc",
        state.oidc_client_id
    );
    Redirect::temporary(&authorize_url)
}

async fn demo_oidc_callback(
    State(state): State<DemoState>,
    Query(query): Query<OidcCallbackQuery>,
) -> impl IntoResponse {
    match state
        .oidc_service
        .exchange_code(
            &query.code,
            &state.oidc_client_id,
            None,
            DEMO_OIDC_CALLBACK,
            None,
        )
        .await
    {
        Ok(tokens) => {
            let userinfo = state
                .oidc_service
                .userinfo(&tokens.access_token)
                .await
                .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }));
            let tokens_json = serde_json::to_string_pretty(&tokens).unwrap();
            let userinfo_json = serde_json::to_string_pretty(&userinfo).unwrap();

            Html(format!(
                r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>OIDC callback</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem auto; max-width: 56rem; line-height: 1.5; padding: 0 1rem; }}
    pre {{ background: #f6f8fa; border-radius: 6px; padding: 1rem; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>OIDC authorization-code flow complete</h1>
  <p><a href="/">Back to example index</a></p>
  <h2>Token response</h2>
  <pre>{}</pre>
  <h2>UserInfo</h2>
  <pre>{}</pre>
</body>
</html>"#,
                escape_html(&tokens_json),
                escape_html(&userinfo_json),
            ))
            .into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<!DOCTYPE html><html><body><h1>OIDC flow failed</h1><pre>{}</pre></body></html>",
                escape_html(&err.to_string())
            )),
        )
            .into_response(),
    }
}

async fn demo_sso_login(Query(query): Query<SsoQuery>) -> Redirect {
    let provider = query
        .provider
        .unwrap_or_else(|| DEMO_FEDERATION_PROVIDER.to_string());
    let begin_url = format!(
        "{BASE_URL}/auth/federation/{provider}/begin?redirect_uri={BASE_URL}/auth/federation/{provider}/callback"
    );
    Redirect::temporary(&begin_url)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
