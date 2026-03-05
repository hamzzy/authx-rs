//! OIDC Provider and Federation route handlers for authx-axum.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Form, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::Deserialize;
use tracing::instrument;

use authx_plugins::{
    oidc_federation::OidcFederationService,
    oidc_provider::{
        jwks_from_public_pem, oidc_discovery_document, DeviceAuthorizationResponse,
        DeviceCodeError, OidcProviderConfig, OidcProviderService,
    },
};

use crate::errors::AuthErrorResponse;
use crate::extractors::RequireAuth;

// ── OIDC Provider (authx as IdP) ─────────────────────────────────────────────

#[derive(Clone)]
pub struct OidcProviderState<S> {
    pub service: Arc<OidcProviderService<S>>,
    pub config: OidcProviderConfig,
    pub issuer: String,
    pub base_path: String,
    pub public_pem: Vec<u8>,
    pub jwks_kid: String,
}

/// Query params for /authorize
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub fn oidc_provider_router<S>(state: OidcProviderState<S>) -> Router
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/authorize", get(authorize_handler::<S>))
        .route("/token", post(token_handler_unified::<S>))
        .route("/userinfo", get(userinfo_handler::<S>))
        .route("/jwks", get(jwks_handler::<S>))
        // Device Authorization Grant (RFC 8628)
        .route(
            "/device_authorization",
            post(device_authorization_handler::<S>),
        )
        .route("/device", get(device_verification_page))
        .route("/device/verify", post(device_verify_handler::<S>))
        .with_state(state)
}

async fn discovery_handler<S>(
    State(state): State<OidcProviderState<S>>,
) -> Json<serde_json::Value> {
    let doc = oidc_discovery_document(&state.issuer, &state.base_path);
    Json(serde_json::to_value(doc).unwrap())
}

#[instrument(skip(state, query))]
async fn authorize_handler<S>(
    State(state): State<OidcProviderState<S>>,
    Query(query): Query<AuthorizeQuery>,
    RequireAuth(identity): RequireAuth,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    if query.response_type != "code" {
        return Err(AuthErrorResponse::from(
            authx_core::error::AuthError::Internal("response_type must be code".into()),
        ));
    }
    let scope = query.scope.unwrap_or_else(|| "openid".into());
    let (_, redirect_url) = state
        .service
        .create_authorization_code(
            identity.user.id,
            &query.client_id,
            &query.redirect_uri,
            &scope,
            query.state.as_deref(),
            query.nonce.as_deref(),
            query.code_challenge.as_deref(),
        )
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok((StatusCode::FOUND, [(header::LOCATION, redirect_url)]))
}

/// Token handler supports authorization_code, refresh_token, and device_code grants.
/// Axum Form extractor works with one struct. We'll use a unified form.
#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub device_code: Option<String>,
}

#[instrument(skip(state, form))]
async fn token_handler_unified<S>(
    State(state): State<OidcProviderState<S>>,
    Form(form): Form<TokenForm>,
) -> axum::response::Response
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    if form.grant_type == "authorization_code" {
        let code = match form.code.as_deref() {
            Some(c) => c,
            None => {
                return AuthErrorResponse::from(authx_core::error::AuthError::Internal(
                    "missing code".into(),
                ))
                .into_response()
            }
        };
        let redirect_uri = match form.redirect_uri.as_deref() {
            Some(r) => r,
            None => {
                return AuthErrorResponse::from(authx_core::error::AuthError::Internal(
                    "missing redirect_uri".into(),
                ))
                .into_response()
            }
        };
        match state
            .service
            .exchange_code(
                code,
                &form.client_id,
                form.client_secret.as_deref(),
                redirect_uri,
                form.code_verifier.as_deref(),
            )
            .await
        {
            Ok(resp) => Json(resp).into_response(),
            Err(e) => AuthErrorResponse::from(e).into_response(),
        }
    } else if form.grant_type == "refresh_token" {
        let rt = match form.refresh_token.as_deref() {
            Some(r) => r,
            None => {
                return AuthErrorResponse::from(authx_core::error::AuthError::Internal(
                    "missing refresh_token".into(),
                ))
                .into_response()
            }
        };
        match state
            .service
            .refresh(
                rt,
                &form.client_id,
                form.client_secret.as_deref(),
                form.scope.as_deref(),
            )
            .await
        {
            Ok(resp) => Json(resp).into_response(),
            Err(e) => AuthErrorResponse::from(e).into_response(),
        }
    } else if form.grant_type == "urn:ietf:params:oauth:grant-type:device_code" {
        let dc = match form.device_code.as_deref() {
            Some(d) => d,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "missing device_code"
                    })),
                )
                    .into_response()
            }
        };
        match state.service.poll_device_code(dc, &form.client_id).await {
            Ok(resp) => Json(resp).into_response(),
            Err(device_err) => {
                let (error_code, error_description) = match device_err {
                    DeviceCodeError::AuthorizationPending => (
                        "authorization_pending",
                        "The user has not yet completed authorization.",
                    ),
                    DeviceCodeError::SlowDown => (
                        "slow_down",
                        "Polling too frequently. Increase interval by 5 seconds.",
                    ),
                    DeviceCodeError::ExpiredToken => (
                        "expired_token",
                        "The device code has expired.",
                    ),
                    DeviceCodeError::AccessDenied => (
                        "access_denied",
                        "The user denied the authorization request.",
                    ),
                };
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": error_code,
                        "error_description": error_description
                    })),
                )
                    .into_response()
            }
        }
    } else {
        AuthErrorResponse::from(authx_core::error::AuthError::Internal(
            "unsupported grant_type".into(),
        ))
        .into_response()
    }
}

#[instrument(skip(state))]
async fn userinfo_handler<S>(
    State(state): State<OidcProviderState<S>>,
    TypedHeader(Authorization(auth)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<serde_json::Value>, AuthErrorResponse>
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let claims = state
        .service
        .userinfo(auth.token())
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(claims))
}

async fn jwks_handler<S>(
    State(state): State<OidcProviderState<S>>,
) -> Result<Json<serde_json::Value>, AuthErrorResponse> {
    let jwks = jwks_from_public_pem(&state.public_pem, &state.jwks_kid)
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(serde_json::to_value(jwks).unwrap()))
}

// ── Device Authorization Grant (RFC 8628) ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationForm {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[instrument(skip(state, form))]
async fn device_authorization_handler<S>(
    State(state): State<OidcProviderState<S>>,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Result<Json<DeviceAuthorizationResponse>, AuthErrorResponse>
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let scope = form.scope.as_deref().unwrap_or("openid");
    let resp = state
        .service
        .request_device_authorization(&form.client_id, scope)
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok(Json(resp))
}

/// Query params for the device verification page.
#[derive(Debug, Deserialize)]
pub struct DeviceVerifyQuery {
    #[serde(default)]
    pub user_code: Option<String>,
}

/// Serve a simple HTML form for the user to enter/confirm their user_code.
async fn device_verification_page(
    Query(query): Query<DeviceVerifyQuery>,
) -> axum::response::Html<String> {
    let prefilled = html_escape(&query.user_code.unwrap_or_default());
    axum::response::Html(format!(
        r#"<!DOCTYPE html>
<html><head><title>Device Authorization</title></head>
<body>
<h1>Authorize Device</h1>
<p>Enter the code shown on your device:</p>
<form method="POST" action="device/verify">
  <input type="text" name="user_code" value="{prefilled}"
         placeholder="XXXX-XXXX" maxlength="9" required />
  <br/><br/>
  <button type="submit" name="action" value="approve">Approve</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
</body></html>"#
    ))
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyForm {
    pub user_code: String,
    pub action: String,
}

#[instrument(skip(state, form))]
async fn device_verify_handler<S>(
    State(state): State<OidcProviderState<S>>,
    RequireAuth(identity): RequireAuth,
    Form(form): Form<DeviceVerifyForm>,
) -> Result<axum::response::Html<&'static str>, AuthErrorResponse>
where
    S: authx_storage::ports::OidcClientRepository
        + authx_storage::ports::AuthorizationCodeRepository
        + authx_storage::ports::OidcTokenRepository
        + authx_storage::ports::DeviceCodeRepository
        + authx_storage::ports::UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let approve = form.action == "approve";
    state
        .service
        .verify_user_code(&form.user_code, identity.user.id, approve)
        .await
        .map_err(AuthErrorResponse::from)?;

    if approve {
        Ok(axum::response::Html(
            "<!DOCTYPE html><html><body><h1>Device authorized successfully. You may close this page.</h1></body></html>",
        ))
    } else {
        Ok(axum::response::Html(
            "<!DOCTYPE html><html><body><h1>Device authorization denied. You may close this page.</h1></body></html>",
        ))
    }
}

// ── OIDC Federation (SSO via Okta, Azure AD, Google Workspace) ────────────────

#[derive(Clone)]
pub struct OidcFederationState<S> {
    pub service: Arc<OidcFederationService<S>>,
}

/// Query for federation begin
#[derive(Debug, Deserialize)]
pub struct FederationBeginQuery {
    pub redirect_uri: String,
}

/// Query for federation callback
#[derive(Debug, Deserialize)]
pub struct FederationCallbackQuery {
    pub code: String,
    pub state: String,
}

/// Build OIDC Federation router. Nest under e.g. `/auth/oidc` for routes
/// `/:provider/begin` and `/:provider/callback`.
pub fn oidc_federation_router<S>(service: Arc<OidcFederationService<S>>) -> Router
where
    S: authx_storage::ports::OidcFederationProviderRepository
        + authx_storage::ports::UserRepository
        + authx_storage::ports::SessionRepository
        + authx_storage::ports::OAuthAccountRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let state = OidcFederationState { service };
    Router::new()
        .route("/:provider/begin", get(federation_begin_handler::<S>))
        .route("/:provider/callback", get(federation_callback_handler::<S>))
        .with_state(state)
}

#[instrument(skip(state, query))]
async fn federation_begin_handler<S>(
    State(state): State<OidcFederationState<S>>,
    Path(provider): Path<String>,
    Query(query): Query<FederationBeginQuery>,
) -> Result<impl IntoResponse, AuthErrorResponse>
where
    S: authx_storage::ports::OidcFederationProviderRepository
        + authx_storage::ports::UserRepository
        + authx_storage::ports::SessionRepository
        + authx_storage::ports::OAuthAccountRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let resp = state
        .service
        .begin(&provider, &query.redirect_uri)
        .await
        .map_err(AuthErrorResponse::from)?;
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, resp.authorization_url)],
    ))
}

#[instrument(skip(state, query))]
async fn federation_callback_handler<S>(
    State(state): State<OidcFederationState<S>>,
    Path(provider): Path<String>,
    Query(query): Query<FederationCallbackQuery>,
) -> Result<(StatusCode, axum::http::HeaderMap, Json<serde_json::Value>), AuthErrorResponse>
where
    S: authx_storage::ports::OidcFederationProviderRepository
        + authx_storage::ports::UserRepository
        + authx_storage::ports::SessionRepository
        + authx_storage::ports::OAuthAccountRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let (user, session, token) = state
        .service
        .callback(&provider, &query.code, &query.state, "")
        .await
        .map_err(AuthErrorResponse::from)?;

    let cookie = crate::cookies::set_session_cookie(&token, 60 * 60 * 24 * 30, false);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie);

    Ok((
        StatusCode::OK,
        headers,
        Json(serde_json::json!({
            "user_id": user.id,
            "session_id": session.id,
            "token": token,
        })),
    ))
}

/// Minimal HTML escaping to prevent XSS in inline HTML values.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
