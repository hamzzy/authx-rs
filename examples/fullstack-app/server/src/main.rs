/// fullstack-app — End-to-end authx-rs example with React frontend + PostgreSQL.
///
/// Demonstrates:
///  - PostgresStore with auto-migration
///  - Email/password sign-up and sign-in
///  - Cookie-based session management
///  - TOTP MFA enrollment and verification
///  - OIDC Provider (authx as IdP) — used by the React SDK
///  - CSRF protection and rate limiting
///  - CORS configured for the Vite dev server
///
/// Run:
///   # 1. Start Postgres
///   docker compose -f examples/fullstack-app/docker-compose.yml up -d
///
///   # 2. Start the backend
///   DATABASE_URL=postgres://authx:authx@localhost:5433/authx cargo run -p fullstack-app
///
///   # 3. Start the React frontend (in another terminal)
///   cd examples/fullstack-app/client && npm install && npm run dev
///
///   # 4. Open http://localhost:5173
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, Method, StatusCode},
    middleware,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use ed25519_dalek::SigningKey;
use pkcs8::LineEnding;
use rand::rngs::OsRng;
use serde::Deserialize;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use authx_axum::{
    csrf_middleware, oidc_provider_router, set_session_cookie, webauthn_router, AuthxState,
    CsrfConfig, OidcProviderState, RateLimitConfig, RateLimitLayer, RequireAuth, SessionLayer,
};
use authx_core::{brute_force::LockoutConfig, events::EventBus};
use authx_core::models::CreateOidcClient;
use authx_core::KeyRotationStore;
use authx_plugins::oidc_provider::{oidc_discovery_document, OidcProviderConfig, OidcProviderService};
use authx_plugins::{
    AdminService, ApiKeyService, OrgService, TotpService, TotpSetup, WebAuthnService,
};
use authx_storage::ports::{OidcClientRepository, OrgRepository};
use authx_storage::PostgresStore;

const BACKEND_URL: &str = "http://localhost:4000";
const FRONTEND_URL: &str = "http://localhost:5173";
const OIDC_REDIRECT_URI: &str = "http://localhost:5173";
const FULLSTACK_OIDC_CLIENT_NAME: &str = "fullstack-app react client";
const WEBAUTHN_RP_ID: &str = "localhost";

#[derive(Clone)]
struct AppState {
    api_keys: Arc<ApiKeyService<PostgresStore>>,
    admin: Arc<AdminService<PostgresStore>>,
    orgs: Arc<OrgService<PostgresStore>>,
    totp: Arc<TotpService<PostgresStore>>,
    pending_totp: Arc<std::sync::Mutex<std::collections::HashMap<uuid::Uuid, TotpSetup>>>,
    oidc_client_id: String,
    oidc_issuer: String,
    oidc_redirect_uri: String,
    session_ttl_secs: i64,
    secure_cookies: bool,
    webauthn_rp_id: String,
    webauthn_rp_origin: String,
}

#[derive(Deserialize)]
struct TotpCodeBody {
    code: String,
}

#[derive(Deserialize)]
struct SessionCookieBody {
    token: String,
}

#[derive(Deserialize)]
struct ApiKeyCreateBody {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_in_days: i64,
    #[serde(default)]
    org_id: Option<uuid::Uuid>,
}

#[derive(Deserialize)]
struct ApiKeyAuthenticateBody {
    raw_key: String,
}

#[derive(Deserialize)]
struct CreateAdminUserBody {
    email: String,
}

#[derive(Deserialize)]
struct BanBody {
    reason: String,
}

#[derive(Deserialize)]
struct CreateOrgBody {
    name: String,
    slug: String,
}

#[derive(Deserialize)]
struct CreateRoleBody {
    name: String,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct CreateInviteBody {
    email: String,
    role_id: uuid::Uuid,
}

#[derive(Deserialize)]
struct AcceptInviteBody {
    token: String,
}

#[derive(Deserialize)]
struct SwitchOrgBody {
    org_id: Option<uuid::Uuid>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,authx=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL env var required");

    let store = PostgresStore::connect(&database_url)
        .await
        .expect("failed to connect to postgres");

    PostgresStore::migrate(&store.pool)
        .await
        .expect("failed to run migrations");

    let secure = false; // set true behind HTTPS

    // ── Auth routes ──────────────────────────────────────────────────────────
    let lockout_cfg = LockoutConfig::new(5, Duration::from_secs(60 * 15));
    let session_ttl_secs = 60 * 60 * 24 * 30; // 30-day sessions
    let authx_state =
        AuthxState::new_with_lockout(store.clone(), session_ttl_secs, secure, lockout_cfg);

    let csrf_config = CsrfConfig::new([BACKEND_URL, FRONTEND_URL]);
    let auth_rate_limit = RateLimitLayer::new(RateLimitConfig::new(30, Duration::from_secs(60)));

    let auth_router = authx_state
        .router()
        .layer(auth_rate_limit)
        .route_layer(middleware::from_fn_with_state(csrf_config, csrf_middleware));

    // ── OIDC Provider ────────────────────────────────────────────────────────
    let (private_pem, public_pem) = generate_demo_ed25519_pems();
    let key_store = KeyRotationStore::new(3);
    key_store
        .add_key("v1", private_pem.as_bytes(), public_pem.as_bytes())
        .expect("test key pair should load");

    let oidc_config = OidcProviderConfig {
        issuer: FRONTEND_URL.into(),
        key_store: key_store.clone(),
        access_token_ttl_secs: 3600,
        id_token_ttl_secs: 3600,
        refresh_token_ttl_secs: 60 * 60 * 24 * 30,
        auth_code_ttl_secs: 600,
        device_code_ttl_secs: 600,
        device_code_interval_secs: 5,
        verification_uri: format!("{FRONTEND_URL}/oidc/device"),
    };

    let oidc_service = Arc::new(OidcProviderService::new(store.clone(), oidc_config.clone()));

    // Seed a public OIDC client for the React frontend.
    let oidc_client = {
        let clients = OidcClientRepository::list(&store, 0, 100)
            .await
            .expect("oidc client listing should work");
        if let Some(existing) = clients
            .into_iter()
            .find(|client| client.name == FULLSTACK_OIDC_CLIENT_NAME)
        {
            existing
        } else {
            OidcClientRepository::create(
                &store,
                CreateOidcClient {
                    name: FULLSTACK_OIDC_CLIENT_NAME.into(),
                    redirect_uris: vec![OIDC_REDIRECT_URI.into()],
                    grant_types: vec![
                        "authorization_code".into(),
                        "refresh_token".into(),
                        "urn:ietf:params:oauth:grant-type:device_code".into(),
                    ],
                    response_types: vec!["code".into()],
                    allowed_scopes: "openid profile email offline_access".into(),
                    secret_hash: String::new(), // public client
                },
            )
            .await
            .expect("oidc client should seed")
        }
    };

    let oidc_state = OidcProviderState {
        service: oidc_service.clone(),
        config: oidc_config,
        issuer: FRONTEND_URL.into(),
        base_path: "/oidc".into(),
        public_pem: public_pem.into_bytes(),
        jwks_kid: "v1".into(),
    };

    let oidc_router = oidc_provider_router(oidc_state);

    // ── TOTP MFA ─────────────────────────────────────────────────────────────
    let totp_service = Arc::new(TotpService::new(store.clone(), "authx fullstack-app"));
    let plugin_events = EventBus::new();
    let api_key_service = Arc::new(ApiKeyService::new(store.clone()));
    let admin_service = Arc::new(AdminService::new(
        store.clone(),
        plugin_events.clone(),
        session_ttl_secs,
    ));
    let org_service = Arc::new(OrgService::new(store.clone(), plugin_events));
    let webauthn_service = Arc::new(
        WebAuthnService::new(
            store.clone(),
            WEBAUTHN_RP_ID,
            FRONTEND_URL,
            Duration::from_secs(600),
            session_ttl_secs,
        )
        .expect("webauthn service should initialize"),
    );
    let app_state = AppState {
        api_keys: api_key_service,
        admin: admin_service,
        orgs: org_service,
        totp: totp_service,
        pending_totp: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        oidc_client_id: oidc_client.client_id.clone(),
        oidc_issuer: FRONTEND_URL.into(),
        oidc_redirect_uri: OIDC_REDIRECT_URI.into(),
        session_ttl_secs,
        secure_cookies: secure,
        webauthn_rp_id: WEBAUTHN_RP_ID.into(),
        webauthn_rp_origin: FRONTEND_URL.into(),
    };

    let totp_router = Router::new()
        .route("/setup", post(totp_begin_setup))
        .route("/confirm", post(totp_confirm_setup))
        .route("/verify", post(totp_verify))
        .route("/status", get(totp_status))
        .with_state(app_state.clone());

    let webauthn = webauthn_router(webauthn_service)
        .layer(RateLimitLayer::new(RateLimitConfig::new(
            30,
            Duration::from_secs(60),
        )))
        .route_layer(middleware::from_fn_with_state(
            CsrfConfig::new([BACKEND_URL, FRONTEND_URL]),
            csrf_middleware,
        ));

    let debug_router = Router::new()
        .route("/config", get(debug_config))
        .with_state(app_state.clone());

    let auth_debug_router = Router::new()
        .route("/session-cookie", post(set_debug_session_cookie))
        .with_state(app_state.clone());

    let plugin_router = Router::new()
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/test", post(test_api_key))
        .route("/api-keys/:id", delete(revoke_api_key))
        .route("/admin/users", get(list_users).post(create_admin_user))
        .route("/admin/users/:id/ban", post(ban_user).delete(unban_user))
        .route("/admin/users/:id/sessions", get(list_user_sessions).delete(revoke_user_sessions))
        .route("/admin/users/:id/impersonate", post(impersonate_user))
        .route("/orgs", post(create_org))
        .route("/orgs/:id", get(get_org))
        .route("/orgs/:id/members", get(list_org_members))
        .route("/orgs/:id/roles", get(list_org_roles).post(create_org_role))
        .route("/orgs/:id/invites", post(create_org_invite))
        .route("/orgs/invites/accept", post(accept_org_invite))
        .route("/orgs/switch", post(switch_org))
        .with_state(app_state.clone());

    // ── CORS (allow Vite dev server) ─────────────────────────────────────────
    let cors = CorsLayer::new()
        .allow_origin(FRONTEND_URL.parse::<header::HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ORIGIN,
            header::COOKIE,
        ])
        .allow_credentials(true);

    // ── Assemble ─────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/health", get(health))
        .route("/me", get(me))
        .route(
            "/.well-known/openid-configuration",
            get(|| async {
                let doc = oidc_discovery_document(FRONTEND_URL, "/oidc");
                Json(doc)
            }),
        )
        .nest("/auth", auth_router)
        .nest("/auth/totp", totp_router)
        .nest("/auth/webauthn", webauthn)
        .nest("/auth/debug", auth_debug_router)
        .nest("/debug", debug_router)
        .nest("/plugins", plugin_router)
        .nest("/oidc", oidc_router)
        .layer(SessionLayer::new(store))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = "0.0.0.0:4000";
    tracing::info!("backend running at {BACKEND_URL}");
    tracing::info!("OIDC client_id = {}", oidc_client.client_id);
    tracing::info!("OIDC discovery: {BACKEND_URL}/oidc/.well-known/openid-configuration");
    tracing::info!("start the React frontend: cd examples/fullstack-app/client && npm run dev");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn generate_demo_ed25519_pems() -> (String, String) {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("generated signing key should serialize to PKCS#8 PEM")
        .to_string();
    let public_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .expect("generated verifying key should serialize to SPKI PEM");

    (private_pem, public_pem)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

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

async fn debug_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "backend_url": BACKEND_URL,
        "frontend_url": FRONTEND_URL,
        "oidc_client_id": state.oidc_client_id,
        "oidc_issuer": state.oidc_issuer,
        "oidc_redirect_uri": state.oidc_redirect_uri,
        "webauthn_rp_id": state.webauthn_rp_id,
        "webauthn_rp_origin": state.webauthn_rp_origin,
    }))
}

async fn set_debug_session_cookie(
    State(state): State<AppState>,
    Json(body): Json<SessionCookieBody>,
) -> impl IntoResponse {
    let cookie = set_session_cookie(&body.token, state.session_ttl_secs, state.secure_cookies);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    )
}

// ── Plugin Routes ────────────────────────────────────────────────────────────

async fn list_api_keys(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<authx_core::models::ApiKey>>, (StatusCode, Json<serde_json::Value>)> {
    let keys = state.api_keys.list(identity.user.id).await.map_err(internal_error)?;
    Ok(Json(keys))
}

async fn create_api_key(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<ApiKeyCreateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let expires_at = chrono::Utc::now() + chrono::Duration::days(body.expires_in_days);
    let resp = state
        .api_keys
        .create(
            identity.user.id,
            body.org_id.or(identity.active_org.as_ref().map(|org| org.id)),
            body.name,
            body.scopes,
            expires_at,
        )
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({
        "key": resp.key,
        "raw_key": resp.raw_key,
    })))
}

async fn revoke_api_key(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(key_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .api_keys
        .revoke(identity.user.id, key_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn test_api_key(
    State(state): State<AppState>,
    Json(body): Json<ApiKeyAuthenticateBody>,
) -> Result<Json<authx_core::models::ApiKey>, (StatusCode, Json<serde_json::Value>)> {
    let key = state
        .api_keys
        .authenticate(&body.raw_key)
        .await
        .map_err(auth_error)?;
    Ok(Json(key))
}

async fn list_users(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<authx_core::models::User>>, (StatusCode, Json<serde_json::Value>)> {
    let users = state.admin.list_users(0, 100).await.map_err(internal_error)?;
    Ok(Json(users))
}

async fn create_admin_user(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateAdminUserBody>,
) -> Result<Json<authx_core::models::User>, (StatusCode, Json<serde_json::Value>)> {
    let user = state
        .admin
        .create_user(identity.user.id, body.email)
        .await
        .map_err(internal_error)?;
    Ok(Json(user))
}

async fn ban_user(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
    Json(body): Json<BanBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .admin
        .ban_user(identity.user.id, user_id, &body.reason)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn unban_user(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .admin
        .unban_user(identity.user.id, user_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_user_sessions(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<authx_core::models::Session>>, (StatusCode, Json<serde_json::Value>)> {
    let sessions = state.admin.list_sessions(user_id).await.map_err(internal_error)?;
    Ok(Json(sessions))
}

async fn revoke_user_sessions(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .admin
        .revoke_all_sessions(identity.user.id, user_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn impersonate_user(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let (_session, token) = state
        .admin
        .impersonate(identity.user.id, user_id, "127.0.0.1")
        .await
        .map_err(internal_error)?;
    let cookie = set_session_cookie(&token, state.session_ttl_secs, state.secure_cookies);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true, "token": token })),
    ))
}

async fn create_org(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateOrgBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (org, membership) = state
        .orgs
        .create(identity.user.id, body.name, body.slug, None)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({
        "org": org,
        "membership": membership,
    })))
}

async fn get_org(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
    Path(org_id): Path<uuid::Uuid>,
) -> Result<Json<authx_core::models::Organization>, (StatusCode, Json<serde_json::Value>)> {
    let org = state.orgs.get(org_id).await.map_err(internal_error)?;
    Ok(Json(org))
}

async fn list_org_members(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
    Path(org_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<authx_core::models::Membership>>, (StatusCode, Json<serde_json::Value>)> {
    let members = state.orgs.list_members(org_id).await.map_err(internal_error)?;
    Ok(Json(members))
}

async fn list_org_roles(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
    Path(org_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<authx_core::models::Role>>, (StatusCode, Json<serde_json::Value>)> {
    let roles = OrgRepository::find_roles(state.admin.storage(), org_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(roles))
}

async fn create_org_role(
    RequireAuth(_identity): RequireAuth,
    State(state): State<AppState>,
    Path(org_id): Path<uuid::Uuid>,
    Json(body): Json<CreateRoleBody>,
) -> Result<Json<authx_core::models::Role>, (StatusCode, Json<serde_json::Value>)> {
    let role = state
        .orgs
        .create_role(org_id, body.name, body.permissions)
        .await
        .map_err(internal_error)?;
    Ok(Json(role))
}

async fn create_org_invite(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Path(org_id): Path<uuid::Uuid>,
    Json(body): Json<CreateInviteBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let invite = state
        .orgs
        .invite_member(org_id, body.email, body.role_id, identity.user.id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({
        "invite": invite.invite,
        "raw_token": invite.raw_token,
    })))
}

async fn accept_org_invite(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<AcceptInviteBody>,
) -> Result<Json<authx_core::models::Membership>, (StatusCode, Json<serde_json::Value>)> {
    let membership = state
        .orgs
        .accept_invite(&body.token, identity.user.id)
        .await
        .map_err(auth_error)?;
    Ok(Json(membership))
}

async fn switch_org(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<SwitchOrgBody>,
) -> Result<Json<authx_core::models::Session>, (StatusCode, Json<serde_json::Value>)> {
    let session = state
        .orgs
        .switch_org(identity.session.id, body.org_id)
        .await
        .map_err(internal_error)?;
    let _ = identity;
    Ok(Json(session))
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": error.to_string() })),
    )
}

fn auth_error(error: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": error.to_string() })),
    )
}

// ── TOTP ──────────────────────────────────────────────────────────────────────

async fn totp_begin_setup(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let setup = state
        .totp
        .begin_setup(identity.user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    let resp = serde_json::json!({
        "otpauth_uri": setup.otpauth_uri,
        "secret": setup.secret_base32,
        "backup_codes": setup.backup_codes,
    });

    state
        .pending_totp
        .lock()
        .unwrap()
        .insert(identity.user.id, setup);

    Ok(Json(resp))
}

async fn totp_confirm_setup(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<TotpCodeBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let setup = state
        .pending_totp
        .lock()
        .unwrap()
        .remove(&identity.user.id)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "No pending TOTP setup. Call /auth/totp/setup first." })),
            )
        })?;

    state
        .totp
        .confirm_setup(identity.user.id, &setup, &body.code)
        .await
        .map_err(|e| {
            state
                .pending_totp
                .lock()
                .unwrap()
                .insert(identity.user.id, setup);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(serde_json::json!({ "ok": true, "message": "TOTP enabled" })))
}

async fn totp_verify(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
    Json(body): Json<TotpCodeBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    use authx_plugins::totp::TotpVerifyRequest;

    state
        .totp
        .verify(TotpVerifyRequest {
            user_id: identity.user.id,
            code: body.code,
        })
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(serde_json::json!({ "ok": true, "message": "TOTP verified" })))
}

async fn totp_status(
    RequireAuth(identity): RequireAuth,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let enabled = state.totp.is_enabled(identity.user.id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    Ok(Json(serde_json::json!({ "enabled": enabled })))
}
