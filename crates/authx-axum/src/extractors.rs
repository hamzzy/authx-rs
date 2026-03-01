use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Json},
};
use serde_json::json;

use authx_core::identity::Identity;

/// Extracts the resolved [`Identity`] from request extensions.
/// Rejects with 401 if the session middleware did not resolve a valid session.
pub struct RequireAuth(pub Identity);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Identity>()
            .cloned()
            .map(RequireAuth)
            .ok_or(AuthRejection::Unauthenticated)
    }
}

/// Extracts an [`Identity`] and verifies role membership.
///
/// Since Axum extractors cannot carry a runtime role parameter, applications
/// use [`RequireAuth`] and then call [`Identity::has_role`] inline, or wrap
/// this struct in their own extractor with a hardcoded role constant.
pub struct RequireRole {
    pub identity: Identity,
}

impl RequireRole {
    pub fn check(identity: Identity, role: &str) -> Result<Self, AuthRejection> {
        if identity.has_role(role) {
            Ok(Self { identity })
        } else {
            Err(AuthRejection::Forbidden)
        }
    }
}

/// Rejection type shared by all auth extractors.
#[derive(Debug)]
pub enum AuthRejection {
    Unauthenticated,
    Forbidden,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AuthRejection::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            AuthRejection::Forbidden       => (StatusCode::FORBIDDEN,    "forbidden"),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}
