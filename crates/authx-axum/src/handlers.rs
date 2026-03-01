use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use authx_core::{brute_force::LockoutConfig, error::AuthError, models::Session};
use authx_plugins::email_password::{EmailPasswordService, SignInRequest, SignUpRequest};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

use crate::{
    cookies::{clear_session_cookie, set_session_cookie},
    errors::AuthErrorResponse,
    extractors::RequireAuth,
};

/// Shared state passed into all auth route handlers.
#[derive(Clone)]
pub struct AuthxState<S> {
    pub service: Arc<EmailPasswordService<S>>,
    pub session_ttl_secs: i64,
    pub secure_cookies: bool,
}

impl<S> AuthxState<S>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, session_ttl_secs: i64, secure_cookies: bool) -> Self {
        use authx_core::events::EventBus;
        let events = EventBus::new();
        let service = Arc::new(EmailPasswordService::new(
            storage,
            events,
            8,
            session_ttl_secs,
        ));
        Self {
            service,
            session_ttl_secs,
            secure_cookies,
        }
    }

    /// Same as [`new`] but with brute-force lockout enabled.
    pub fn new_with_lockout(
        storage: S,
        session_ttl_secs: i64,
        secure_cookies: bool,
        lockout: LockoutConfig,
    ) -> Self {
        use authx_core::events::EventBus;
        let events = EventBus::new();
        let service = Arc::new(
            EmailPasswordService::new(storage, events, 8, session_ttl_secs).with_lockout(lockout),
        );
        Self {
            service,
            session_ttl_secs,
            secure_cookies,
        }
    }

    /// Build the auth router — nest this under `/auth` in your application.
    pub fn router(self) -> Router {
        Router::new()
            .route("/sign-up", post(sign_up::<S>))
            .route("/sign-in", post(sign_in::<S>))
            .route("/sign-out", post(sign_out::<S>))
            .route("/sign-out/all", post(sign_out_all::<S>))
            .route("/session", get(get_session))
            .route("/sessions", get(list_sessions::<S>))
            .route("/sessions/:id", delete(revoke_session::<S>))
            .with_state(self)
    }
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct SignUpBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct SignUpResponse {
    user_id: Uuid,
    email: String,
}

#[derive(Deserialize)]
struct SignInBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct SignInResponse {
    user_id: Uuid,
    session_id: Uuid,
    /// Raw opaque token — store this client-side or read from cookie.
    token: String,
}

#[derive(Serialize)]
struct SessionView {
    id: Uuid,
    user_id: Uuid,
    ip_address: String,
    org_id: Option<Uuid>,
    expires_at: String,
    created_at: String,
}

impl From<Session> for SessionView {
    fn from(s: Session) -> Self {
        Self {
            id: s.id,
            user_id: s.user_id,
            ip_address: s.ip_address,
            org_id: s.org_id,
            expires_at: s.expires_at.to_rfc3339(),
            created_at: s.created_at.to_rfc3339(),
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[instrument(skip(state, body))]
async fn sign_up<S>(
    State(state): State<AuthxState<S>>,
    Json(body): Json<SignUpBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    // IP is not available at the handler level without a real extractor;
    // leave empty for now — a ConnectInfo extractor handles this in the example app.
    let user = state
        .service
        .sign_up(SignUpRequest {
            email: body.email,
            password: body.password,
            ip: String::new(),
        })
        .await
        .map_err(AuthErrorResponse::from)?;

    tracing::info!(user_id = %user.id, "sign-up complete");
    Ok((
        StatusCode::CREATED,
        Json(SignUpResponse {
            user_id: user.id,
            email: user.email,
        }),
    ))
}

#[instrument(skip(state, body))]
async fn sign_in<S>(
    State(state): State<AuthxState<S>>,
    Json(body): Json<SignInBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    let resp = state
        .service
        .sign_in(SignInRequest {
            email: body.email,
            password: body.password,
            ip: String::new(),
        })
        .await
        .map_err(AuthErrorResponse::from)?;

    let cookie = set_session_cookie(&resp.token, state.session_ttl_secs, state.secure_cookies);

    tracing::info!(user_id = %resp.user.id, "sign-in complete");

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(SignInResponse {
            user_id: resp.user.id,
            session_id: resp.session.id,
            token: resp.token,
        }),
    ))
}

#[instrument(skip(state, identity))]
async fn sign_out<S>(
    State(state): State<AuthxState<S>>,
    RequireAuth(identity): RequireAuth,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    state
        .service
        .sign_out(identity.session.id)
        .await
        .map_err(AuthErrorResponse::from)?;

    let cookie = clear_session_cookie(state.secure_cookies);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    ))
}

#[instrument(skip(state, identity))]
async fn sign_out_all<S>(
    State(state): State<AuthxState<S>>,
    RequireAuth(identity): RequireAuth,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    state
        .service
        .sign_out_all(identity.user.id)
        .await
        .map_err(AuthErrorResponse::from)?;

    let cookie = clear_session_cookie(state.secure_cookies);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    ))
}

async fn get_session(RequireAuth(identity): RequireAuth) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user":    identity.user,
        "session": SessionView::from(identity.session),
        "active_org": identity.active_org,
    }))
}

#[instrument(skip(state, identity))]
async fn list_sessions<S>(
    State(state): State<AuthxState<S>>,
    RequireAuth(identity): RequireAuth,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    let sessions = state
        .service
        .list_sessions(identity.user.id)
        .await
        .map_err(AuthErrorResponse::from)?;

    let views: Vec<SessionView> = sessions.into_iter().map(Into::into).collect();
    Ok(Json(views))
}

#[instrument(skip(state, identity))]
async fn revoke_session<S>(
    State(state): State<AuthxState<S>>,
    RequireAuth(identity): RequireAuth,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    // Validate the session belongs to this user before revoking.
    let sessions = state
        .service
        .list_sessions(identity.user.id)
        .await
        .map_err(AuthErrorResponse::from)?;

    if !sessions.iter().any(|s| s.id == session_id) {
        return Err(AuthErrorResponse::from(AuthError::SessionNotFound));
    }

    state
        .service
        .sign_out(session_id)
        .await
        .map_err(AuthErrorResponse::from)?;

    Ok((StatusCode::OK, Json(serde_json::json!({ "ok": true }))))
}
