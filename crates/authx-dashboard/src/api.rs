use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use authx_storage::ports::{
    AuditLogRepository, DeviceCodeRepository, OidcClientRepository,
    OidcFederationProviderRepository, OrgRepository, SessionRepository, UserRepository,
};

use crate::DashboardState;

// ── Request / response DTOs ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct Pagination {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_limit")]
    limit: u32,
}
fn default_limit() -> u32 {
    25
}

#[derive(Deserialize)]
pub(crate) struct BanBody {
    reason: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateUserBody {
    email: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateClientBody {
    name: String,
    redirect_uris: String,
    #[serde(default = "default_client_scopes")]
    scopes: String,
    #[serde(default)]
    client_secret: Option<String>,
}

fn default_client_scopes() -> String {
    "openid profile email".into()
}

#[derive(Deserialize)]
pub(crate) struct CreateFederationBody {
    name: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_client_scopes")]
    scopes: String,
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
}

fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(ApiError { error: "not_found" }))
}
fn server_error() -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: "internal_error",
        }),
    )
}

// ── Router ─────────────────────────────────────────────────────────────────────

pub(crate) fn routes<S>() -> Router<DashboardState<S>>
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    Router::new()
        // Users
        .route("/users", get(list_users::<S>))
        .route("/users", post(create_user::<S>))
        .route("/users/{id}", get(get_user::<S>))
        .route("/users/{id}/ban", post(ban_user::<S>))
        .route("/users/{id}/ban", delete(unban_user::<S>))
        .route("/users/{id}/sessions", get(list_sessions::<S>))
        .route("/users/{id}/sessions", delete(revoke_sessions::<S>))
        // OIDC
        .route("/oidc/clients", get(list_oidc_clients::<S>))
        .route("/oidc/clients", post(create_oidc_client::<S>))
        .route("/oidc/federation", get(list_oidc_federation::<S>))
        .route("/oidc/federation", post(create_oidc_federation::<S>))
        // Device codes
        .route("/oidc/device-codes", get(list_device_codes::<S>))
}

// ── Handlers ───────────────────────────────────────────────────────────────────

async fn list_users<S>(
    State(state): State<DashboardState<S>>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.list_users(p.offset, p.limit).await {
        Ok(users) => Json(users).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: list_users failed");
            server_error().into_response()
        }
    }
}

async fn create_user<S>(
    State(state): State<DashboardState<S>>,
    Json(body): Json<CreateUserBody>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let admin_id = Uuid::nil(); // system-level call; no actor session in dashboard
    match state.admin.create_user(admin_id, body.email).await {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: create_user failed");
            server_error().into_response()
        }
    }
}

async fn get_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.get_user(id).await {
        Ok(user) => Json(user).into_response(),
        Err(_) => not_found().into_response(),
    }
}

async fn ban_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id): Path<Uuid>,
    Json(body): Json<BanBody>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.ban_user(Uuid::nil(), id, &body.reason).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: ban_user failed");
            server_error().into_response()
        }
    }
}

async fn unban_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.unban_user(Uuid::nil(), id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: unban_user failed");
            server_error().into_response()
        }
    }
}

async fn list_sessions<S>(
    State(state): State<DashboardState<S>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.list_sessions(id).await {
        Ok(sessions) => Json(sessions).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: list_sessions failed");
            server_error().into_response()
        }
    }
}

async fn revoke_sessions<S>(
    State(state): State<DashboardState<S>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    match state.admin.revoke_all_sessions(Uuid::nil(), id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: revoke_sessions failed");
            server_error().into_response()
        }
    }
}

// ── OIDC Clients ───────────────────────────────────────────────────────────────

async fn list_oidc_clients<S>(
    State(state): State<DashboardState<S>>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let storage = state.admin.storage();
    match OidcClientRepository::list(storage, p.offset, p.limit).await {
        Ok(clients) => Json(clients).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: list_oidc_clients failed");
            server_error().into_response()
        }
    }
}

async fn create_oidc_client<S>(
    State(state): State<DashboardState<S>>,
    Json(body): Json<CreateClientBody>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let storage = state.admin.storage();
    let redirect_uris: Vec<String> = body
        .redirect_uris
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "invalid_redirect_uris",
            }),
        )
            .into_response();
    }

    let secret_hash = body
        .client_secret
        .as_ref()
        .map(|s| authx_core::crypto::sha256_hex(s.as_bytes()))
        .unwrap_or_default();

    match OidcClientRepository::create(
        storage,
        authx_core::models::CreateOidcClient {
            name: body.name.clone(),
            redirect_uris,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            allowed_scopes: body.scopes.clone(),
            secret_hash,
        },
    )
    .await
    {
        Ok(client) => (StatusCode::CREATED, Json(client)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: create_oidc_client failed");
            server_error().into_response()
        }
    }
}

// ── OIDC Federation Providers ──────────────────────────────────────────────────

async fn list_oidc_federation<S>(State(state): State<DashboardState<S>>) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let storage = state.admin.storage();
    match OidcFederationProviderRepository::list_enabled(storage).await {
        Ok(providers) => Json(providers).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: list_oidc_federation failed");
            server_error().into_response()
        }
    }
}

async fn create_oidc_federation<S>(
    State(state): State<DashboardState<S>>,
    Json(body): Json<CreateFederationBody>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let storage = state.admin.storage();

    // For now, the dashboard expects the server to provide an encryption key
    // via configuration; the OIDC federation service already uses that same
    // key. Reuse that here by delegating token encryption to the service in
    // application code — the dashboard only accepts plaintext secrets.
    //
    // Here we simply store the secret as-is; production apps should wire this
    // endpoint to the same encryption key used by `OidcFederationService`.
    let secret_enc = body.client_secret.clone();

    match OidcFederationProviderRepository::create(
        storage,
        authx_core::models::CreateOidcFederationProvider {
            name: body.name.clone(),
            issuer: body.issuer.clone(),
            client_id: body.client_id.clone(),
            secret_enc,
            scopes: body.scopes.clone(),
        },
    )
    .await
    {
        Ok(provider) => (StatusCode::CREATED, Json(provider)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: create_oidc_federation failed");
            server_error().into_response()
        }
    }
}

// ── Device Codes ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct DeviceCodeQuery {
    client_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_limit")]
    limit: u32,
}

async fn list_device_codes<S>(
    State(state): State<DashboardState<S>>,
    Query(q): Query<DeviceCodeQuery>,
) -> impl IntoResponse
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let storage = state.admin.storage();
    match DeviceCodeRepository::list_by_client(storage, &q.client_id, q.offset, q.limit).await {
        Ok(codes) => Json(codes).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard: list_device_codes failed");
            server_error().into_response()
        }
    }
}
