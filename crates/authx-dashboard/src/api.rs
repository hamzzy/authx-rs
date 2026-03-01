use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use authx_storage::ports::{AuditLogRepository, OrgRepository, SessionRepository, UserRepository};

use crate::DashboardState;

// ── Request / response DTOs ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct Pagination {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_limit")]
    limit:  u32,
}
fn default_limit() -> u32 { 25 }

#[derive(Deserialize)]
pub(crate) struct BanBody {
    reason: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateUserBody {
    email: String,
}

#[derive(Serialize)]
struct ApiError { error: &'static str }

fn not_found()    -> impl IntoResponse { (StatusCode::NOT_FOUND,    Json(ApiError { error: "not_found" })) }
fn server_error() -> impl IntoResponse { (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: "internal_error" })) }

// ── Router ─────────────────────────────────────────────────────────────────────

pub(crate) fn routes<S>() -> Router<DashboardState<S>>
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    Router::new()
        // Users
        .route("/users",                   get(list_users::<S>))
        .route("/users",                   post(create_user::<S>))
        .route("/users/{id}",              get(get_user::<S>))
        .route("/users/{id}/ban",          post(ban_user::<S>))
        .route("/users/{id}/ban",          delete(unban_user::<S>))
        .route("/users/{id}/sessions",     get(list_sessions::<S>))
        .route("/users/{id}/sessions",     delete(revoke_sessions::<S>))
}

// ── Handlers ───────────────────────────────────────────────────────────────────

async fn list_users<S>(
    State(state): State<DashboardState<S>>,
    Query(p):     Query<Pagination>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.list_users(p.offset, p.limit).await {
        Ok(users) => Json(users).into_response(),
        Err(e)    => { tracing::error!(error = %e, "dashboard: list_users failed"); server_error().into_response() }
    }
}

async fn create_user<S>(
    State(state): State<DashboardState<S>>,
    Json(body):   Json<CreateUserBody>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    let admin_id = Uuid::nil(); // system-level call; no actor session in dashboard
    match state.admin.create_user(admin_id, body.email).await {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(e)   => { tracing::error!(error = %e, "dashboard: create_user failed"); server_error().into_response() }
    }
}

async fn get_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id):     Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.get_user(id).await {
        Ok(user)  => Json(user).into_response(),
        Err(_)    => not_found().into_response(),
    }
}

async fn ban_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id):     Path<Uuid>,
    Json(body):   Json<BanBody>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.ban_user(Uuid::nil(), id, &body.reason).await {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => { tracing::error!(error = %e, "dashboard: ban_user failed"); server_error().into_response() }
    }
}

async fn unban_user<S>(
    State(state): State<DashboardState<S>>,
    Path(id):     Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.unban_user(Uuid::nil(), id).await {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => { tracing::error!(error = %e, "dashboard: unban_user failed"); server_error().into_response() }
    }
}

async fn list_sessions<S>(
    State(state): State<DashboardState<S>>,
    Path(id):     Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.list_sessions(id).await {
        Ok(sessions) => Json(sessions).into_response(),
        Err(e)       => { tracing::error!(error = %e, "dashboard: list_sessions failed"); server_error().into_response() }
    }
}

async fn revoke_sessions<S>(
    State(state): State<DashboardState<S>>,
    Path(id):     Path<Uuid>,
) -> impl IntoResponse
where
    S: UserRepository + SessionRepository + OrgRepository + AuditLogRepository
        + Clone + Send + Sync + 'static,
{
    match state.admin.revoke_all_sessions(Uuid::nil(), id).await {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => { tracing::error!(error = %e, "dashboard: revoke_sessions failed"); server_error().into_response() }
    }
}
