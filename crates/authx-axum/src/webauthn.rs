use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
use serde::Deserialize;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use authx_plugins::{FinishAuthenticationRequest, FinishRegistrationRequest, WebAuthnService};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

use crate::errors::AuthErrorResponse;

#[derive(Clone)]
struct WebAuthnState<S> {
    service: Arc<WebAuthnService<S>>,
}

pub fn webauthn_router<S>(service: Arc<WebAuthnService<S>>) -> Router
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/register/begin", post(begin_registration::<S>))
        .route("/register/finish", post(finish_registration::<S>))
        .route("/login/begin", post(begin_login::<S>))
        .route("/login/finish", post(finish_login::<S>))
        .with_state(WebAuthnState { service })
}

#[derive(Deserialize)]
struct BeginBody {
    user_id: Uuid,
}

#[derive(Deserialize)]
struct FinishRegistrationBody {
    challenge: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct FinishLoginBody {
    challenge: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    ip: String,
}

async fn begin_registration<S>(
    State(state): State<WebAuthnState<S>>,
    Json(body): Json<BeginBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    let resp = state
        .service
        .begin_registration(body.user_id)
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(resp))
}

async fn finish_registration<S>(
    State(state): State<WebAuthnState<S>>,
    Json(body): Json<FinishRegistrationBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    let resp = state
        .service
        .finish_registration(FinishRegistrationRequest {
            challenge: body.challenge,
            credential: body.credential,
        })
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(resp))
}

async fn begin_login<S>(
    State(state): State<WebAuthnState<S>>,
    Json(body): Json<BeginBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    let resp = state
        .service
        .begin_authentication(body.user_id)
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(resp))
}

async fn finish_login<S>(
    State(state): State<WebAuthnState<S>>,
    Json(body): Json<FinishLoginBody>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    let resp = state
        .service
        .finish_authentication(FinishAuthenticationRequest {
            challenge: body.challenge,
            credential: body.credential,
            ip: body.ip,
        })
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(resp))
}
