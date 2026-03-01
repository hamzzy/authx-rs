use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use authx_core::error::AuthError;

/// Newtype wrapper so we can implement axum's [`IntoResponse`] for
/// [`AuthError`] without violating the orphan rule.
pub struct AuthErrorResponse(pub AuthError);

impl From<AuthError> for AuthErrorResponse {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

impl IntoResponse for AuthErrorResponse {
    fn into_response(self) -> Response {
        let err = &self.0;
        let (status, code) = match err {
            AuthError::InvalidCredentials      => (StatusCode::UNAUTHORIZED,          "invalid_credentials"),
            AuthError::UserNotFound            => (StatusCode::NOT_FOUND,             "user_not_found"),
            AuthError::SessionNotFound         => (StatusCode::UNAUTHORIZED,          "session_not_found"),
            AuthError::EmailTaken              => (StatusCode::CONFLICT,              "email_taken"),
            AuthError::EmailNotVerified        => (StatusCode::FORBIDDEN,             "email_not_verified"),
            AuthError::InvalidToken            => (StatusCode::UNAUTHORIZED,          "invalid_token"),
            AuthError::AccountLocked           => (StatusCode::TOO_MANY_REQUESTS,     "account_locked"),
            AuthError::Forbidden(_)            => (StatusCode::FORBIDDEN,             "forbidden"),
            AuthError::HashError(_)
            | AuthError::EncryptionError(_)
            | AuthError::Internal(_)
            | AuthError::Storage(_)            => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        tracing::warn!(status = status.as_u16(), error = code, detail = %err);
        (status, Json(json!({ "error": code, "message": err.to_string() }))).into_response()
    }
}
