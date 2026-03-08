use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use tracing::instrument;

/// CSRF protection via trusted-origin check.
///
/// For state-mutating methods (POST/PUT/PATCH/DELETE), the `Origin` or
/// `Referer` header must match one of the configured trusted origins.
/// Safe methods (GET, HEAD, OPTIONS) pass through unconditionally.
#[derive(Clone)]
pub struct CsrfConfig {
    pub trusted_origins: Vec<String>,
}

impl CsrfConfig {
    pub fn new(origins: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            trusted_origins: origins.into_iter().map(|s| s.into()).collect(),
        }
    }
}

#[instrument(skip(config, request, next), fields(method = %request.method(), path = %request.uri().path()))]
pub async fn csrf_middleware(
    axum::extract::State(config): axum::extract::State<CsrfConfig>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();

    // Safe methods are always allowed.
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(request).await;
    }

    let origin = request
        .headers()
        .get(header::ORIGIN)
        .or_else(|| request.headers().get(header::REFERER))
        .and_then(|v| v.to_str().ok());

    let trusted = match origin {
        None => {
            tracing::warn!("csrf: no origin header on mutating request");
            false
        }
        Some(origin) => config
            .trusted_origins
            .iter()
            .any(|trusted| origin.starts_with(trusted.as_str())),
    };

    if !trusted {
        tracing::warn!(origin = ?origin, "csrf: untrusted origin rejected");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "csrf_violation", "message": "untrusted origin" })),
        )
            .into_response();
    }

    next.run(request).await
}
