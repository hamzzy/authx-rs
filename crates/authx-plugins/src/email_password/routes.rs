use axum::{http::StatusCode, response::IntoResponse, routing::post, Router};

use authx_storage::ports::{SessionRepository, UserRepository};

use super::service::EmailPasswordService;

/// Build the router for the email/password plugin.
/// Nest under `/auth` in the application router.
pub fn router<S>(_svc: std::sync::Arc<EmailPasswordService<S>>) -> Router
where
    S: UserRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/sign-up", post(not_implemented))
        .route("/sign-in", post(not_implemented))
        .route("/sign-out", post(not_implemented))
}

async fn not_implemented() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "wire via AuthxState in authx-axum")
}
