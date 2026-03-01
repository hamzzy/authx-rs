use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use tracing::instrument;

use authx_core::{
    crypto::sha256_hex,
    identity::Identity,
};
use authx_storage::ports::{SessionRepository, UserRepository};

const SESSION_HEADER: &str = "x-authx-token";
const SESSION_COOKIE: &str = "authx_session";

/// Extracts session token from `Authorization: Bearer <token>`, the
/// `x-authx-token` header, or the `authx_session` cookie (in that order),
/// resolves it against storage, and inserts an [`Identity`] extension so
/// downstream extractors can access it.
///
/// Routes that do not require auth still pass through — the identity is just
/// absent from extensions. Use [`RequireAuth`] to enforce authentication.
#[instrument(skip(storage, request, next))]
pub async fn session_middleware<S>(
    axum::extract::State(storage): axum::extract::State<S>,
    mut request: Request,
    next: Next,
) -> Response
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
{
    if let Some(identity) = resolve_identity(&storage, &request).await {
        request.extensions_mut().insert(identity);
        tracing::debug!("identity resolved");
    }

    next.run(request).await
}

async fn resolve_identity<S>(storage: &S, request: &Request) -> Option<Identity>
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
{
    let raw_token = extract_token(request)?;
    let token_hash = sha256_hex(raw_token.as_bytes());

    let session = storage.find_by_token_hash(&token_hash).await.ok()??;

    if session.expires_at < chrono::Utc::now() {
        tracing::debug!(session_id = %session.id, "session expired");
        return None;
    }

    let user = storage.find_by_id(session.user_id).await.ok()??;

    Some(Identity::new(user, session))
}

fn extract_token(request: &Request) -> Option<String> {
    // 1. Authorization: Bearer <token>
    if let Some(bearer) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.to_owned());
    }

    // 2. x-authx-token header
    if let Some(token) = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_owned());
    }

    // 3. authx_session cookie
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;

    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(value.to_owned());
        }
    }

    None
}
